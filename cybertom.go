package box

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/biter777/countries"
	"github.com/google/uuid"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/showwin/speedtest-go/speedtest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	commontom "example/pkg/common"
	cp "example/pkg/cp"
	"example/pkg/rttmeasurer"
	commonpb "example/proto/common"
	cppb "example/proto/cp"
	fppb "example/proto/fp"
)

type registerUserTask struct {
	user any
	done chan struct{}
}

type deleteUserTask struct {
	deleted []string
}

type CyberTom struct {
	fppb.UnimplementedFPServer
	cp cppb.CPClient

	// tag -> map[userID]User
	//
	// There is no necessity to synchronize due to
	// the fact that this map is accessed serially.
	users map[string]map[string]any

	registerUserCh chan any // chan registerUserTask/deleteUserTask
	tomLogger      *slog.Logger
	config         *option.TomConfig

	box                 *Box
	inboundOptionByType map[string]*option.Inbound

	currentCert []byte
	currentKey  []byte
	mmdb        []byte

	totalUsersCount atomic.Int64
	maxBandwidth    float64
}

func NewCyberTom(config *option.TomConfig) *CyberTom {
	tom := CyberTom{
		config:         config,
		users:          make(map[string]map[string]any),
		registerUserCh: make(chan any),
		maxBandwidth:   0,
	}
	return &tom
}

func basicAuth(next http.Handler, username, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		authParts := strings.SplitN(auth, " ", 2)
		if len(authParts) != 2 || authParts[0] != "Basic" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(authParts[1])
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || pair[0] != username || pair[1] != password {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *CyberTom) startTom() error {
	opts := &slog.HandlerOptions{}
	if s.config.Debug {
		opts.Level = slog.LevelDebug
	}
	handler := slog.NewTextHandler(os.Stdout, opts)
	s.tomLogger = slog.New(handler)

	s.inboundOptionByType = make(map[string]*option.Inbound)
	for _, inbound := range s.box.options.Inbounds {
		s.inboundOptionByType[inbound.Type] = &inbound
	}

	data, err := ioutil.ReadFile(s.config.JWTPublicKeyPath)
	if err != nil {
		panic(err)
	}
	s.config.JWTPublic = data
	// lis, err := net.Listen("tcp", s.config.GRPCBind)
	// if err != nil {
	//     return fmt.Errorf("CyberTom Start: failed to listen: %w", err)
	// }
	// srv := grpc.NewServer()
	// fppb.RegisterFPServer(srv, s)
	// go func() {
	//     if err := srv.Serve(lis); err != nil {
	//         panic(fmt.Errorf("Cyber Start: failed to serve: %w", err))
	//     }
	// }()

	ip, city, country_code, loc, asn, err := getIPInfo()

	if err != nil {
		s.tomLogger.Error("error:", err)
		os.Exit(1)
	}

	s.config.ProxyAddress = ip
	s.config.City = city
	s.config.Location = loc
	s.config.ASN = asn
	s.config.CountryCode = country_code
	s.config.CountryName = countries.ByName(country_code).String()
	if s.config.CountryName == countries.Unknown.String() {
		s.tomLogger.Error("Country code is not valid", "country_code", country_code)
		os.Exit(1)
	}
	s.tomLogger.Info("IP Info", "ip", ip, "city", city, "location", loc, "asn", asn, "country_code", country_code, "country_name", s.config.CountryName)

	domin, err := s.ip2domain(ip)

	s.config.HTTPEndpoint = fmt.Sprintf("https://%s", domin+s.config.HTTPEndpoint)

	s.tomLogger.Info("FP Start", "ip", ip, "domain", domin)

	// regexp turn 89018207.fp.example.com to 89018207
	s.config.ID = "Cybertom-" + regexp.MustCompile(`\D`).ReplaceAllString(domin, "")

	// Get the TLS certificate

	s.currentCert, s.currentKey, s.mmdb, err = s.getTLSCertificateAndMMDB()

	tlsConfig := &tls.Config{
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := tls.X509KeyPair(s.currentCert, s.currentKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load certificate: %v", err)
			}
			return &cert, nil
		},
	}

	// Create HTTP handler with routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/user", s.PutUserHandler())

	// Configure HTTPS server
	httpsServer := &http.Server{
		Addr:         s.config.HTTPSBind,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)), // Force HTTP/1.1
	}

	// Configure HTTP server
	httpServer := &http.Server{
		Addr:    s.config.HTTPBind, // Example: ":8080"
		Handler: mux,               // Shared mux for HTTP and HTTPS
	}

	go s.certCheckLoop()

	// Start HTTPS server
	go func() {
		s.tomLogger.Info("Starting HTTPS server on " + s.config.HTTPSBind)
		if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("HTTPS server failed: %v", err))
		}
	}()

	// Start HTTP server
	go func() {
		s.tomLogger.Info("Starting HTTP server on " + s.config.HTTPBind)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			panic(fmt.Sprintf("HTTP server failed: %v", err))
		}
	}()

	// GRPC
	creds, err := credentials.NewClientTLSFromFile(s.config.CPCertificatePath, "cpapi.example.com")
	if err != nil {
		return fmt.Errorf("Failed to create TLS credentials: %w", err)
	}

	// Prometheus metrics
	go func() {
		metricsAddr := s.config.MonitorAddr
		http.Handle("/metrics", basicAuth(promhttp.Handler(), "prometheus", "132="))
		s.tomLogger.Info("Starting metrics server", "address", metricsAddr)
		if err := http.ListenAndServe(metricsAddr, nil); err != nil {
			s.tomLogger.Error("Metrics server failed", "error", err)
		}
	}()

	conn, err := grpc.Dial(s.config.CPGRPCAddress, grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("did not connect: %w", err)
	}

	client := cppb.NewCPClient(conn)
	s.cp = client
	s.RecoverUsers()
	slog.Debug("FP recovered.")
	go s.HeartBeatLoop()
	go s.registerUserLoop()

	// Speedtest
	var speedtestClient = speedtest.New()
	serverList, err := speedtestClient.FetchServers()
	if err != nil {
		s.tomLogger.Error("FetchServers error", "error", err)
	}
	targets, err := serverList.FindServer([]int{})
	if err != nil {
		s.tomLogger.Error("FindServer error", "error", err)
	}
	for _, speedtestServer := range targets {
		speedtestServer.PingTest(nil)
		speedtestServer.DownloadTest()
		// speedtestServer.UploadTest()
		// Note: The unit of s.DLSpeed, s.ULSpeed is bytes per second, this is a float64.
		s.tomLogger.Info("Speedtest", "Latency", speedtestServer.Latency.String(), "Download", speedtestServer.DLSpeed.String())
		s.maxBandwidth = float64(speedtestServer.DLSpeed)
		speedtestServer.Context.Reset() // reset counter
	}

	return nil
}

func (s *CyberTom) certCheckLoop() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		<-ticker.C
		newCert, newKey, _, err := s.getTLSCertificateAndMMDB()
		if err != nil {
			s.tomLogger.Error("Failed to fetch certificates", "error", err)
			continue
		}

		if !bytes.Equal(s.currentCert, newCert) || !bytes.Equal(s.currentKey, newKey) {
			_, err := tls.X509KeyPair(newCert, newKey)
			if err != nil {
				s.tomLogger.Error("Invalid new certificate", "error", err)
				continue
			}

			s.currentCert = newCert
			s.currentKey = newKey
			s.tomLogger.Info("Certificate updated successfully")
		} else {
			s.tomLogger.Info("Certificate unchanged")
		}
	}
}

// CORSMiddleware handles CORS headers
func CORSMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "PUT, POST, GET, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, UserID, DeviceID")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	}
}

func getIPInfo() (string, string, string, string, string, error) {
	const url = "https://ipinfo.io"
	const maxRetries = 3

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", "", "", "", "", fmt.Errorf("getIPInfo: failed to create request: %v", err)
		}
		req.Header.Set("User-Agent", "curl/7.54.1")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			return "", "", "", "", "", fmt.Errorf("getIPInfo: failed to send request: %v", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response on attempt %d: %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}

		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			lastErr = fmt.Errorf("getIPInfo: failed to parse JSON on attempt %d: %v", i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}

		return result["ip"], result["city"], result["country"], result["loc"], result["org"], nil
	}

	return "", "", "", "", "", fmt.Errorf("getIPInfo: all retries failed: %v", lastErr)
}

func (s *CyberTom) ip2domain(ip string) (string, error) {
	url := fmt.Sprintf("https://%s/1111-1111-1111-11-111", "example.com")
	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Set("ipv4", ip)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
	}
	defer resp.Body.Close()

	type IpDomainResponse struct {
		ClientIP       string `json:"client_ip"`
		ResolvedDomain string `json:"resolved_domain"`
	}

	var ipDomainResp IpDomainResponse
	if err := json.NewDecoder(resp.Body).Decode(&ipDomainResp); err != nil {
		return "", err
	}

	return ipDomainResp.ResolvedDomain, nil
}

func (s *CyberTom) getTLSCertificateAndMMDB() ([]byte, []byte, []byte, error) {
	username := "certd"
	password := "1-1-1-1-1"

	// Helper function to perform authenticated GET request
	fetch := func(url string) ([]byte, error) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.SetBasicAuth(username, password)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		return ioutil.ReadAll(resp.Body)
	}

	// Fetch cert and key
	certData, err := fetch("https://example.com/example.com.crt")
	if err != nil {
		return nil, nil, nil, err
	}

	keyData, err := fetch("https://example.com/example.com.key")
	if err != nil {
		return nil, nil, nil, err
	}

	mmdb, err := fetch("https://example.com//GeoLite2-Country.mmdb")
	if err != nil {
		return nil, nil, nil, err
	}

	return certData, keyData, mmdb, nil
}

func (s *CyberTom) inboundOptionToProxy(inboundOption *option.Inbound, user, password string) *commonpb.Proxy {
	switch inboundOption.Type {
	case "shadowsocks":
		return &commonpb.Proxy{
			Type: commonpb.ProxyType_shadowsocks,
			Data: &commonpb.Proxy_Shadowsocks{
				Shadowsocks: &commonpb.ProxyShadowsocks{
					Server:     s.config.ProxyAddress,
					ServerPort: int32(inboundOption.ShadowsocksOptions.ListenPort),
					Method:     inboundOption.ShadowsocksOptions.Method,
					Password:   password,
					Multiplex:  inboundOption.ShadowsocksOptions.Multiplex.ToProto(),
				},
			},
		}
	case "vless":
		return &commonpb.Proxy{
			Type: commonpb.ProxyType_vless,
			Data: &commonpb.Proxy_Vless{
				Vless: &commonpb.ProxyVLESS{
					Server:     s.config.ProxyAddress,
					ServerPort: int32(inboundOption.VLESSOptions.ListenPort),
					Uuid:       password,
					Tls:        inboundOption.VLESSOptions.TLS.ToProto(),
				},
			},
		}
	case "hysteria2":
		return &commonpb.Proxy{
			Type: commonpb.ProxyType_hysteria2,
			Data: &commonpb.Proxy_Hysteria2{
				Hysteria2: &commonpb.ProxyHysteria2{
					Server:     s.config.ProxyAddress,
					ServerPort: int32(inboundOption.Hysteria2Options.ListenPort),
					Password:   password,
					Tls:        inboundOption.Hysteria2Options.TLS.ToProto(),
				},
			},
		}
	case C.TypeHTTP:
		return &commonpb.Proxy{
			Type: commonpb.ProxyType_http,
			Data: &commonpb.Proxy_Http{
				Http: &commonpb.ProxyHTTP{
					Server:     s.config.ProxyAddress,
					ServerPort: int32(inboundOption.HTTPOptions.ListenPort),
					Username:   user,
					Password:   password,
				},
			},
		}
	}
	return nil
}

type PutUserResponse struct {
	cp.Node
}

func (r *PutUserResponse) ToUser(userID, deviceID, password string) any {
	id := newUserKey(userID, deviceID)
	switch r.Config.Type {
	case "shadowsocks":
		return &option.ShadowsocksUser{Name: id, Password: password}
	case "hysteria2":
		return &option.Hysteria2User{Name: id, Password: password}
	case "vless":
		return &option.VLESSUser{Name: id, UUID: password}
	case "http":
		return &auth.User{Username: id, Password: password}
	}

	return nil
}

func (s *CyberTom) NewPassword(inboundOption *option.Inbound) (string, error) {
	switch inboundOption.Type {
	case "shadowsocks":
		return s.newShadowsocksPassword(inboundOption.ShadowsocksOptions.Method)
	case "hysteria2":
		return s.newHysteria2Password()
	case "vless":
		return s.newVlessPassword()
	case C.TypeHTTP:
		return s.newHTTPPassword()
	}
	return "", nil
}

func (s *CyberTom) newHTTPPassword() (string, error) {
	const charset = "312321"
	const length = 16
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i, v := range b {
		b[i] = charset[v%byte(len(charset))]
	}
	return string(b), nil
}
func (s *CyberTom) newVlessPassword() (string, error) {
	return uuid.NewString(), nil
}

func (s *CyberTom) newHysteria2Password() (string, error) {
	const alphanum = "12312"
	var bytes = make([]byte, 16)
	n, err := rand.Read(bytes)
	if n != len(bytes) || err != nil {
		return "", err
	}
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes), nil
}

func (s *CyberTom) isProtocolSupported(protocol string) bool {
	for _, supported := range s.config.SupportedProtocol {
		if supported == protocol {
			return true
		}
	}
	return false
}

func (s *CyberTom) newShadowsocksPassword(method string) (string, error) {
	var pskLen int
	switch method {
	case "2022-blake3-aes-128-gcm":
		pskLen = 16
	case "2022-blake3-aes-256-gcm":
		pskLen = 32
	default:
		return "", errors.New("unsupported method")
	}

	bytes := make([]byte, pskLen)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	randomString := base64.StdEncoding.EncodeToString(bytes)

	return randomString, nil
}

func (s *CyberTom) PutUserHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, UserID, DeviceID")
			w.WriteHeader(http.StatusNoContent)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}

		conn, buf, err := hijacker.Hijack()
		if err != nil {
			log.Printf("Failed to hijack connection: %v", err)
			return
		}
		defer conn.Close()

		writeErrorResponse := func(statusCode int, message string) {
			buf.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode)))
			buf.WriteString("Access-Control-Allow-Origin: *\r\n")
			buf.WriteString("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n")
			buf.WriteString("Access-Control-Allow-Headers: Content-Type, Authorization, UserID, DeviceID\r\n")
			buf.WriteString("Content-Type: text/plain\r\n")
			buf.WriteString("\r\n")
			buf.WriteString(message)
			buf.Flush()
		}

		rttMs := rttmeasurer.Handler(conn, r)
		s.tomLogger.Debug("PutUserHandler", "rtt", rttMs)

		authHeader := r.Header.Get("Authorization")
		userID := r.Header.Get("UserID")
		deviceID := r.Header.Get("DeviceID")
		s.tomLogger.Debug("PutUserHandler", "userID", userID, "deviceID", deviceID, "authorization", authHeader)

		if !strings.HasPrefix(authHeader, "Bearer ") {
			writeErrorResponse(http.StatusBadRequest, "Bad authorization header")
			return
		}

		token := authHeader[len("Bearer "):]
		if err := commontom.ValidateJWTToken(token, s.config.JWTPublic, userID, deviceID, s.config.Level); err != nil {
			writeErrorResponse(http.StatusUnauthorized, fmt.Sprintf("Invalid token: %v", err))
			return
		}

		db, err := maxminddb.FromBytes(s.mmdb)
		if err != nil {
			log.Printf("MaxMind DB loading error: %v", err)
			writeErrorResponse(http.StatusInternalServerError, "Internal server error")
			return
		}
		defer db.Close()

		type LocationData struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("Invalid remote address: %v", err)
			writeErrorResponse(http.StatusBadRequest, "Invalid remote address")
			return
		}

		var record LocationData
		err = db.Lookup(netip.MustParseAddr(ip)).Decode(&record)
		if err != nil {
			log.Printf("MaxMind DB lookup error: %v", err)
			writeErrorResponse(http.StatusInternalServerError, "Location lookup failed")
			return
		}

		countryCode := record.Country.ISOCode
		s.tomLogger.Debug("Country Code: " + countryCode)

		var protocol string
		switch countryCode {
		case "CN":
			protocol = C.TypeVLESS
		case "RU", "IR":
			protocol = C.TypeHysteria2
		default:
			protocol = C.TypeShadowsocks
		}

		if rttMs > 100 {
			protocol = C.TypeHysteria2
		}

		if !s.isProtocolSupported(protocol) {
			protocol = s.config.DefaultProtocol
		}

		s.tomLogger.Debug("protocol: " + protocol)

		inboundOption, ok := s.inboundOptionByType[protocol]
		if !ok {
			writeErrorResponse(http.StatusBadRequest, fmt.Sprintf("Unsupported inbound type: %s", protocol))
			return
		}

		password, err := s.NewPassword(inboundOption)
		if err != nil {
			writeErrorResponse(http.StatusInternalServerError, fmt.Sprintf("New password error: %v", err))
			return
		}

		resp := PutUserResponse{
			Node: cp.Node{
				NodeID:      s.config.ID,
				City:        s.config.City,
				CountryCode: s.config.CountryCode,
				CountryName: s.config.CountryName,
				Location:    s.config.Location,
				ASN:         s.config.ASN,
				Cap:         s.config.CapacityList,
				Endpoint:    s.config.HTTPEndpoint,
				Config:      cp.Proxy2Config(s.inboundOptionToProxy(inboundOption, userID, password)),
			},
		}

		done := make(chan struct{})
		s.registerUserCh <- registerUserTask{user: resp.ToUser(userID, deviceID, password), done: done}
		<-done

		if protocol == C.TypeShadowsocks {
			resp.Config.Shadowsocks.Password = s.inboundOptionByType["shadowsocks"].ShadowsocksOptions.Password + ":" + password
		} else if protocol == C.TypeVLESS {
			resp.Config.Vless.Tls.Reality.PublicKey = s.config.PublicKey
			resp.Config.Vless.Tls.Reality.ShortId = ""
		}

		data, err := json.Marshal(resp)
		if err != nil {
			writeErrorResponse(http.StatusInternalServerError, fmt.Sprintf("Marshal error: %v", err))
			return
		}

		buf.WriteString("HTTP/1.1 200 OK\r\n")
		buf.WriteString("Access-Control-Allow-Origin: *\r\n")
		buf.WriteString("Content-Type: application/json\r\n")
		buf.WriteString("\r\n")
		buf.Write(data)
		buf.Flush()
	}
}

func (s *CyberTom) ToFP() *commonpb.FP {
	var proxyList []*commonpb.Proxy

	for _, inbound := range s.inboundOptionByType {
		proxyList = append(proxyList, s.inboundOptionToProxy(inbound, "UNKNOWN", "UNKNOWN"))
	}
	var userList []string
	for _, userMap := range s.users {
		for user, _ := range userMap {
			userList = append(userList, user)
		}
	}

	fp := &commonpb.FP{
		Id:           s.config.ID,
		Address:      s.config.ProxyAddress,
		MonitorAddr:  s.config.MonitorAddr,
		HttpEndpoint: s.config.HTTPEndpoint,
		City:         s.config.City,
		CountryCode:  s.config.CountryCode,
		CountryName:  s.config.CountryName,
		Location:     s.config.Location,
		Asn:          s.config.ASN,
		CapacityList: s.config.CapacityList,
		ProxyList:    proxyList,
		UserList:     userList,
		Congestion:   s.calculateServerLoad(),
	}
	return fp
}

func (s *CyberTom) HeartBeart() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := &cppb.HeartBeatRequest{
		Fp:    s.ToFP(),
		Level: 0,
	}
	s.tomLogger.Debug("HeartBeart", "req", req)
	resp, err := s.cp.HeartBeat(ctx, req)
	if err != nil {
		s.tomLogger.Error("HeartBeart", "resp", err)
	}
	if resp != nil && len(resp.DeletedUserkey) > 0 {
		s.registerUserCh <- deleteUserTask{deleted: resp.DeletedUserkey}
	}
}

func (s *CyberTom) HeartBeatLoop() {
	timer := time.NewTicker(time.Second * 5)
	for {
		select {
		case <-s.box.done:
			return
		case <-timer.C:
			s.HeartBeart()
		}
	}
}

const proxyUserKeyFmt = "%s-%s"

func newUserKey(userID, deviceID string) string {
	return fmt.Sprintf(proxyUserKeyFmt, userID, deviceID)
}

func userToTag(user any) string {
	switch user.(type) {
	case *option.VLESSUser:
		return "vless"
	case *option.Hysteria2User:
		return "hysteria2"
	case *option.ShadowsocksUser:
		return "shadowsocks"
	case *auth.User:
		return "http"
	}
	return ""
}

func (s *CyberTom) registerUserLoop() {
	for t := range s.registerUserCh {
		switch task := t.(type) {
		case registerUserTask: // from PutUserHandler
			s.tomLogger.Debug("registerUserLoop", task)
			user := task.user
			tag := userToTag(user)
			if _, ok := s.users[tag]; !ok {
				s.users[tag] = make(map[string]any)
			}
			switch u := user.(type) {
			case *option.Hysteria2User:
				s.users[tag][u.Name] = user
			case *option.ShadowsocksUser:
				s.users[tag][u.Name] = user
			case *option.VLESSUser:
				s.users[tag][u.Name] = user
			case *auth.User:
				s.users[tag][u.Username] = user
				for _, inbound := range s.box.inbounds {
					if inbound.Type() == C.TypeHTTP {
						httpInbound, ok := inbound.(*pkginbound.HTTP)
						if !ok {
							panic("failed to cast inbound to HTTP")
						}
						s.updateHTTPUser(httpInbound, u)
						break
					}
				}
				continue
			default:
				s.tomLogger.Error("registerUserTask", "unknown user type", user)
				continue
			}

			s.tomLogger.Debug("registerUserTask", "users", s.users)
			s.updateUsersToSingBox()
			close(task.done)
		case deleteUserTask: // from cp HeartBeat
			s.tomLogger.Debug("DeleteUsers", "users before delete", s.users)
			s.tomLogger.Debug("DeleteUsers", "users to delete", task.deleted)
			for _, userMap := range s.users {
				for _, key := range task.deleted {
					delete(userMap, key)
				}
			}

			s.tomLogger.Debug("deleteUserTask", "users", s.users)
			s.updateUsersToSingBox()
		}
	}
}

func (s *CyberTom) updateUsersToSingBox() {
	// Calculate total users across all protocols
	userCount := 0
	for _, userMap := range s.users {
		userCount += len(userMap)
	}
	metrics.UserCount.WithLabelValues("total").Set(float64(userCount))
	s.totalUsersCount.Store(int64(userCount))

	tag2userList := make(map[string][]any)
	for tag, userMap := range s.users {
		for _, user := range userMap {
			tag2userList[tag] = append(tag2userList[tag], user)
		}
	}
	for _, inbound := range s.box.inbounds {
		tag := inbound.Type()
		if _, ok := tag2userList[tag]; ok {
			s.updateUsers(inbound, tag2userList[tag])
			metrics.UserCount.WithLabelValues(tag).Set(float64(len(tag2userList[tag])))
		}
	}
}

func protoToShadowsocksUser(user *commonpb.User) option.ShadowsocksUser {
	u := user.Data.(*commonpb.User_Shadowsocks)
	return option.ShadowsocksUser{Name: u.Shadowsocks.Name, Password: u.Shadowsocks.Password}
}

func protoToVlessUser(user *commonpb.User) option.VLESSUser {
	u := user.Data.(*commonpb.User_Vless)
	return option.VLESSUser{UUID: u.Vless.Uuid, Name: u.Vless.Name, Flow: u.Vless.Flow}

}

func protoToHysteria2User(user *commonpb.User) option.Hysteria2User {
	u := user.Data.(*commonpb.User_Hysteria2)
	return option.Hysteria2User{Name: u.Hysteria2.Name, Password: u.Hysteria2.Password}
}

func (s *CyberTom) updateUsers(inbound adapter.Inbound, users []any) {
	switch in := inbound.(type) {
	case *pkginbound.ShadowsocksMulti:
		var ul []option.ShadowsocksUser
		for _, user := range users {
			u := user.(*option.ShadowsocksUser)
			ul = append(ul, *u)
		}
		s.updateShadowsocksUsers(in, ul)
		persistUsers[option.ShadowsocksUser](ul)
	case *pkginbound.VLESS:
		var ul []option.VLESSUser
		for _, user := range users {
			u := user.(*option.VLESSUser)
			ul = append(ul, *u)
		}
		s.updateVLESSUsers(in, ul)
		persistUsers[option.VLESSUser](ul)
	case *pkginbound.Hysteria2:
		var ul []option.Hysteria2User
		for _, user := range users {
			u := user.(*option.Hysteria2User)
			ul = append(ul, *u)
		}
		s.updateHysteria2Users(in, ul)
		persistUsers[option.Hysteria2User](ul)
	}
}

func (s *CyberTom) updateHTTPUser(inbound *pkginbound.HTTP, user *auth.User) {
	inbound.UpdateUser(user)
}
func (s *CyberTom) updateShadowsocksUsers(inbound *pkginbound.ShadowsocksMulti, users []option.ShadowsocksUser) {
	inbound.UpdateUserPassword(users)
}
func (s *CyberTom) updateVLESSUsers(inbound *pkginbound.VLESS, users []option.VLESSUser) {
	inbound.UpdateUsers(users)
}
func (s *CyberTom) updateHysteria2Users(inbound *pkginbound.Hysteria2, users []option.Hysteria2User) {
	inbound.UpdateUsers(users)
}

func persistUsers[T any](users []T) {
	if len(users) == 0 {
		return
	}

	userType := reflect.TypeOf(users[0]).Name()
	data, err := json.Marshal(users)
	if err != nil {
		return
	}
	if err := os.WriteFile(fmt.Sprintf("%s.json", userType), data, 0o644); err != nil {
		return
	}
}

func recoverUsers[T any]() ([]*T, error) {
	var e T
	typeName := reflect.TypeOf(e).Name()

	var users []*T
	if _, err := os.Stat(fmt.Sprintf("%s.json", typeName)); err != nil {
		return nil, nil
	}
	data, err := os.ReadFile(fmt.Sprintf("%s.json", typeName))
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &users); err != nil {
		return nil, err
	}

	return users, nil
}

func (s *CyberTom) RecoverUsers() {
	if users, err := recoverUsers[option.VLESSUser](); err == nil {
		if _, ok := s.users["vless"]; !ok {
			s.users["vless"] = make(map[string]any)
		}
		for _, user := range users {
			s.users["vless"][user.Name] = user
		}
	}

	if users, err := recoverUsers[option.ShadowsocksUser](); err == nil {
		if _, ok := s.users["shadowsocks"]; !ok {
			s.users["shadowsocks"] = make(map[string]any)
		}
		for _, user := range users {
			s.users["shadowsocks"][user.Name] = user
		}
	}

	if users, err := recoverUsers[option.Hysteria2User](); err == nil {
		if _, ok := s.users["hysteria2"]; !ok {
			s.users["hysteria2"] = make(map[string]any)
		}
		for _, user := range users {
			s.users["hysteria2"][user.Name] = user
		}
	}

	if users, err := recoverUsers[auth.User](); err == nil {
		if _, ok := s.users[C.TypeHTTP]; !ok {
			s.users[C.TypeHTTP] = make(map[string]any)
		}
		for _, user := range users {
			s.users[C.TypeHTTP][user.Username] = user
		}
	}
	tag2userList := make(map[string][]any)
	s.tomLogger.Debug("registerUserLoop", "users", s.users)
	for tag, userMap := range s.users {
		for _, user := range userMap {
			tag2userList[tag] = append(tag2userList[tag], user)
		}
	}
	for _, inbound := range s.box.inbounds {
		tag := inbound.Type()
		if _, ok := tag2userList[tag]; ok {
			s.updateUsers(inbound, tag2userList[tag])
		}
	}
}

func (s *CyberTom) calculateServerLoad() float64 {

	userCount := s.totalUsersCount.Load()

	currentBandwidth, err := metrics.GetDownloadBandwidth()
	if err != nil {
		s.tomLogger.Error("GetDownloadBandwidth error", "error", err)
		currentBandwidth = s.maxBandwidth
	}

	connections, err := metrics.GetConnectionsCount()
	if err != nil {
		s.tomLogger.Error("GetConnectionsCount error", "error", err)
		connections = 65535.0
	}

	memoryUsage, memoryLeft, err := metrics.GetMemoryStats()
	if err != nil {
		memoryUsage = 0.9
		memoryLeft = 50 << 20 // 50MB
	}

	s.tomLogger.Debug("calculateServerLoad", "userCount", float64(userCount), "connections", connections, "currentBandwidth", currentBandwidth/1000/1000, "maxBandwidth", s.maxBandwidth/1000/1000, "memoryUsage", memoryUsage, "memoryLeft", memoryLeft)

	score := metrics.CalculateLoadScore(float64(userCount), connections, currentBandwidth, s.maxBandwidth, memoryUsage, memoryLeft)
	s.tomLogger.Debug("calculateServerLoad", "score", score)

	metrics.Congestion.Set(score)
	metrics.CurrentBandwidth.Set(currentBandwidth / 1000 / 1000)
	metrics.MaxBandwidth.Set(s.maxBandwidth / 1000 / 1000)
	metrics.Connections.Set(connections)

	return score
}
