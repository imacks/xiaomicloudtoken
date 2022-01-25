package main

import (
	"crypto/hmac"
	"crypto/md5"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"
)

type APICred struct {
	UserName string
	PasswordHash string
	UserID string
	ServiceToken string
	Cookies []*http.Cookie

	ssecurity string
}

func (cred *APICred) SignRequest(urlPath, dataParam string) (string, string, error) {
	logi("signing request to %s", urlPath)

	epochMilli := time.Now().UnixNano()/1000/1000
	nonceSuffix := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceSuffix[0:], uint32(epochMilli/60000))

	nonceBytes := make([]byte, 12)
	_, err := crand.Read(nonceBytes)
	if err != nil {
		return "", "", err
	}
	for i := 8; i < 12; i++ {
		nonceBytes[i] = nonceSuffix[i-8]
	}
	nonceBase64 := base64.StdEncoding.EncodeToString(nonceBytes[:])
	logi("derived nonce: %s", nonceBase64)

	ssecurityBytes, err := base64.StdEncoding.DecodeString(cred.ssecurity)
	if err != nil {
		return "", "", err
	}

	nonceSignData := make([]byte, len(nonceBytes)+len(ssecurityBytes))
	for i := 0; i < len(ssecurityBytes); i++ {
		nonceSignData[i] = ssecurityBytes[i]
	}
	for i := len(ssecurityBytes); i < len(nonceBytes)+len(ssecurityBytes); i++ {
		nonceSignData[i] = nonceBytes[i-len(ssecurityBytes)]
	}

	nonceSignedBytes := sha256.Sum256(nonceSignData)
	nonceSignedBase64 := base64.StdEncoding.EncodeToString(nonceSignedBytes[:])
	logi("derived sign nonce: %s", nonceSignedBase64)

	signParams := []string{
		strings.Replace(urlPath, "/app", "", -1),
		nonceSignedBase64,
		nonceBase64,
		fmt.Sprintf("data=%s", dataParam),
	}
	signParamsStr := strings.Join(signParams, "&")
	hmacHasher := hmac.New(sha256.New, nonceSignedBytes[:])
	hmacHasher.Write([]byte(signParamsStr))
	signatureBytes := hmacHasher.Sum(nil)
	signatureBase64 := base64.StdEncoding.EncodeToString(signatureBytes[:])
	logi("derived signature: %s", signatureBase64)

	return nonceBase64, signatureBase64, nil
}

func (cred *APICred) String() string {
	return fmt.Sprintf("username: %s\n", cred.UserName) +
		fmt.Sprintf("passwd_hash: %s\n", cred.PasswordHash) +
		fmt.Sprintf("user_id: %s\n", cred.UserID) +
		fmt.Sprintf("service_token: %s\n", cred.ServiceToken) +
		fmt.Sprintf("ssecurity: %s\n", cred.ssecurity)
}

func doLogin(client *http.Client, username, password string) (*APICred, error) {
	// string is already utf-8 in go
	passwordHash := strings.ToUpper(fmt.Sprintf("%x", md5.Sum([]byte(password))))

	// first go to get _sign
	response1, cookies, err := doLogin1(client, username)
	if err != nil {
		return nil, err
	}

	// second go gets most of the stuff
	var response2 map[string]string
	response2, cookies, err = doLogin2(client, username, passwordHash, response1, cookies)
	if err != nil {
		return nil, err
	}

	// last go gets the service token
	var serviceToken string
	serviceToken, cookies, err = doLogin3(client, response2, cookies)
	if err != nil {
		return nil, err
	}

	cred := &APICred{
		UserName: username,
		PasswordHash: passwordHash,
		Cookies: cookies,
		UserID: response2["userId"],
		ServiceToken: serviceToken,

		ssecurity: response2["ssecurity"],
	}
	
	if debugMode {
		fmt.Fprintf(os.Stdout, "----- credential data -----\n")
		fmt.Fprintln(os.Stdout, cred.String())
		fmt.Fprintln(os.Stdout, "cookies:")
		for _, v := range cred.Cookies {
			fmt.Fprintf(os.Stdout, "  %s\n", v.Raw)
		}
		fmt.Fprintf(os.Stdout, "----- /credential data -----\n")		
	} else {
		logi("signed in with user id %s (%s)", cred.UserID, cred.UserName)
	}
	return cred, nil
}

func doLogin1(client *http.Client, username string) (map[string]string, []*http.Cookie, error) {
	loginURL := "https://account.xiaomi.com/pass/serviceLogin?sid=xiaomiio&_json=true"
	logi("http get %s", loginURL)
	req, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{
		Name: "userId",
		Value: username,
	})

	response, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		logw("server responded with status code %d", response.StatusCode)
	}

	contentBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	if debugMode {
		fmt.Fprintf(os.Stdout, "----- login1 server response -----\n")
		fmt.Fprintln(os.Stdout, string(contentBytes))
		fmt.Fprintf(os.Stdout, "----- /login1 server response -----\n")
	}

	jsonResponse, err := parseJSONWithHeader(contentBytes)
	if err != nil {
		return nil, nil, err
	}

	_, ok := jsonResponse["_sign"]
	if !ok {
		return nil, nil, fmt.Errorf("cannot parse server response: expect JSON with field _sign")
	}

	return jsonResponse, response.Cookies(), nil
}

func doLogin2(client *http.Client, username, passwdHash string, lastResponse map[string]string, cookies []*http.Cookie) (map[string]string, []*http.Cookie, error) {
	loginURL := "https://account.xiaomi.com/pass/serviceLoginAuth2"
	logi("http post %s", loginURL)
	req, err := http.NewRequest(http.MethodPost, loginURL, nil)
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCommonCookies(req)

	q := req.URL.Query()
	q.Add("sid", "xiaomiio")
	q.Add("callback", "https://sts.api.io.mi.com/sts")
	q.Add("qs", "%3Fsid%3Dxiaomiio%26_json%3Dtrue")
	q.Add("_json", "true")
	q.Add("user", username)
	q.Add("_sign", lastResponse["_sign"])
	q.Add("hash", passwdHash)
	req.URL.RawQuery = q.Encode()

	response, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		logw("server responded with status code %d", response.StatusCode)
	}

	contentBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	if debugMode {
		fmt.Fprintf(os.Stdout, "----- login2 server response -----\n")
		fmt.Fprintln(os.Stdout, string(contentBytes))
		fmt.Fprintf(os.Stdout, "----- /login2 server response -----\n")
	}

	jsonResponse, err := parseJSONWithHeader(contentBytes)
	if err != nil {
		return nil, nil, err
	}

	if jsonResponse["result"] != "ok" {
		return nil, nil, fmt.Errorf("authentication failed")
	}
	if len(jsonResponse["ssecurity"]) < 4 {
		return nil, nil, fmt.Errorf("invalid ssecurity value")
	}

	return jsonResponse, response.Cookies(), nil
}

func doLogin3(client *http.Client, lastResponse map[string]string, cookies []*http.Cookie) (string, []*http.Cookie, error) {
	loginURL := lastResponse["location"]
	logi("http get %s", loginURL)
	req, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		return "", nil, err
	}

	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	addCommonCookies(req)
	for _, v := range cookies {
		req.AddCookie(v)
	}

	response, err := client.Do(req)
	if err != nil {
		return "", nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		logw("server responded with status code %d", response.StatusCode)
	}

	contentBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return "", nil, err
	}

	if string(contentBytes) != "ok" {
		return "", nil, fmt.Errorf("server returned invalid response: %s", string(contentBytes))
	}
	serviceToken := ""
	for _, v := range response.Cookies() {
		if v.Name == "serviceToken" {
			serviceToken = v.Value
			break
		}
	}
	if len(serviceToken) == 0 {
		return "", nil, fmt.Errorf("service did not return service token")
	}
	return serviceToken, mergeCookies(cookies, response.Cookies()), nil
}

// helpers

func addCommonCookies(req *http.Request) {
	for _, v := range []string{"mi.com", "xiaomi.com"} {
		req.AddCookie(&http.Cookie{
			Name: "sdkVersion",
			Value: "accountsdk-18.8.15",
			Domain: v,
		})
		req.AddCookie(&http.Cookie{
			Name: "deviceId",
			Value: getDeviceID(),
			Domain: v,
		})
	}
}

func mergeCookies(a, b []*http.Cookie) []*http.Cookie {
	result := []*http.Cookie{}
	for _, v := range b {
		result = append(result, v)
	}
	for _, v := range a {
		isOverriden := false
		for _, w := range b {
			if v.Domain == w.Domain && v.Name == w.Name {
				isOverriden = true
			}
		}
		if !isOverriden {
			result = append(result, v)
		}
	}
	return result
}

func parseJSONList(data []byte) ([]json.RawMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("server returned empty response")
	}
	var result []json.RawMessage
	err := json.Unmarshal(data, &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}

func parseJSON(data []byte) (map[string]string, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("server returned empty response")
	}

	var jsonResponse map[string]json.RawMessage
	err := json.Unmarshal(data, &jsonResponse)
	if err != nil {
		return nil, err
	}

	result := map[string]string{}
	for k, v := range jsonResponse {
		vRaw := string(v)
		if strings.HasPrefix(vRaw, "\"") && strings.HasSuffix(vRaw, "\"") {
			result[k] = vRaw[1:len(vRaw)-1]
		} else {
			result[k] = vRaw
		}
	}
	return result, nil
}

func parseJSONWithHeader(data []byte) (map[string]string, error) {
	const magicHeader = "&&&START&&&"
	if !strings.HasPrefix(string(data), magicHeader) {
		return nil, fmt.Errorf("server returned invalid response")
	}

	return parseJSON(data[len(magicHeader):])
}

var singletonUA string
func getUserAgent() string {
	if len(singletonUA) > 0 {
		return singletonUA
	}

	charRange := []string{"A", "B", "C", "D", "E"}
	randSuffix := ""
	for i := 0; i < 13; i++ {
		randSuffix += charRange[rand.Intn(len(charRange))]
	}
	singletonUA = fmt.Sprintf("Android-7.1.1-1.0.0-ONEPLUS A3010-136-%s APP/xiaomi.smarthome APPV/62830", randSuffix)
	if verbose {
		logi("generated useragent %s", singletonUA)
	}
	return singletonUA
}

var singletonDeviceID string
func getDeviceID() string {
	if len(singletonDeviceID) > 0 {
		return singletonDeviceID
	}

	// a-z
	charRange := []byte{}
	for i := 97; i < 122; i++ {
		charRange = append(charRange, byte(i))
	}

	deviceID := ""
	for i := 0; i < 6; i++ {
		deviceID += string(charRange[rand.Intn(len(charRange))])
	}
	singletonDeviceID = deviceID
	if verbose {
		logi("generated device id %s", singletonDeviceID)
	}
	return singletonDeviceID
}