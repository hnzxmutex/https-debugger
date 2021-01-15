package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	rd "math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/polvi/sni"
)

var (
	//根证书
	caKey  *rsa.PrivateKey
	caCert *x509.Certificate
	//http请求客户端
	client = &http.Client{
		//不捕捉302跳转,原样返回
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	//格式化字符串
	formatString = "\nbody==============================\n%s\nend================================\n"
	//域名缓存
	hostCertMap sync.Map
)

//快速处理error
func orPanic(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	https_addr := flag.String("l", ":30080", "listen addr")
	flag.Parse()

	parseCA()

	ln, err := net.Listen("tcp", *https_addr)

	orPanic(err)

	hh := httpHandler{}

	log.Fatal(http.Serve(mockListener{ln}, hh))
}

type httpHandler struct{}

// 处理请求并打印
func (h httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqBody, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Println("客户端请求失败", err)
		w.WriteHeader(500)
		return
	}
	log.Printf("新情求:"+formatString, string(reqBody))

	//计算时间
	start := time.Now()

	//转发请求
	resp, err := doProxyReq(reqBody)
	if err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	//回写
	if err := writeResponse(w, resp); err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	//计算消耗时间
	log.Printf("消耗时间:%s\n", time.Now().Sub(start))
}

// 转发请求到真实服务器
func doProxyReq(reqBody []byte) (*http.Response, error) {
	proxyReq, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqBody)))
	proxyReq.RequestURI = ""
	proxyReq.URL = &url.URL{
		Scheme:   "https",
		Host:     proxyReq.Host,
		Path:     proxyReq.URL.Path,
		RawQuery: proxyReq.URL.RawQuery,
	}
	if err != nil {
		return nil, fmt.Errorf("build req fail:%v", err)
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		return nil, fmt.Errorf("client do fail:%v", err)
	}
	return resp, nil
}

// 返回请求数据到客户端
func writeResponse(w http.ResponseWriter, resp *http.Response) error {
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()

	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	respBody, err := httputil.DumpResponse(resp, true)
	resp.Body.Close()

	if err != nil {
		return fmt.Errorf("proxy read body fail %v", err)
	}

	for k, headers := range resp.Header {
		for _, header := range headers {
			w.Header().Set(k, header)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
	log.Printf("返回值:"+formatString, string(respBody))
	return nil
}

// 读取ca文件
func parseCA() {
	caFile, err := ioutil.ReadFile("./cert/ca.crt")
	orPanic(err)
	caBlock, _ := pem.Decode(caFile)
	cert, err := x509.ParseCertificate(caBlock.Bytes)
	orPanic(err)

	keyFile, err := ioutil.ReadFile("./cert/ca.key")
	orPanic(err)
	keyBlock, _ := pem.Decode(keyFile)
	k, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	orPanic(err)

	caKey = k
	caCert = cert
}

//根据域名签发证书
func signCert(host string) tls.Certificate {
	if cert, ok := hostCertMap.Load(host); ok {
		return cert.(tls.Certificate)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(rd.Int63()), //证书序列号
		Issuer:       caCert.Subject,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now(),                   //证书有效期开始时间
		NotAfter:              time.Now().AddDate(10, 0, 0), //证书有效期结束时间
		BasicConstraintsValid: true,                         //基本的有效性约束
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, //证书用途
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	} else {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	orPanic(err)
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &certPrivKey.PublicKey, caKey)
	orPanic(err)
	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	certPrivKeyPEM := new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	serverCert, err := tls.X509KeyPair(certPEM.Bytes(), certPrivKeyPEM.Bytes())
	orPanic(err)

	hostCertMap.Store(host, serverCert)
	return serverCert
}

// 模拟net.Listener,为了自签名证书,接管连接层
type mockListener struct {
	ln net.Listener
}

// 模拟net.Conn.Accept,处理tls握手
func (m mockListener) Accept() (net.Conn, error) {
	c, err := m.ln.Accept()

	if err != nil {
		return c, err
	}
	//读取sni协议里的域名
	host, cc, err := sni.ServerNameFromConn(c)
	if host == "" {
		return c, fmt.Errorf("Cannot support non-SNI enabled clients")
	}

	return tls.Server(cc, &tls.Config{
		Certificates: []tls.Certificate{signCert(host)},
	}), nil
}

// mock Close
func (m mockListener) Close() error {
	return m.ln.Close()
}

// mock Addr
func (m mockListener) Addr() net.Addr {
	return m.ln.Addr()
}
