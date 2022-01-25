package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

var (
	verbose bool
	debugMode bool
	serverCountry string
	beaconDID string
	isBeaconMode bool
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, "Usage: %s [-v] [--country <s>] [--did <s>] user pass\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.BoolVar(&verbose, "v", false, "verbose mode")
	flag.BoolVar(&debugMode, "debug", false, "show server responses")
	flag.StringVar(&serverCountry, "country", "CN", "server country")
	flag.StringVar(&beaconDID, "did", "", "(for BLE) beacon DID")
}

func main() {
	flag.Parse()
	if len(beaconDID) > 0 {
		isBeaconMode = true
	}

	if flag.NArg() != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-v] [--country <s>] [--did <s>] user pass\n", os.Args[0])
		os.Exit(1)
	}

	username := flag.Arg(0)
	password := flag.Arg(1)

	client := &http.Client{}
	cred, err := doLogin(client, username, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}

	var apiURL, dataParam string
	if !isBeaconMode {
		apiURL, dataParam = getDevicesRequest()
	} else {
		apiURL, dataParam = getBeaconRequest(beaconDID)
	}
	result, err := doAPIQuery(client, serverCountry, apiURL, dataParam, cred)
	if err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(result))
}

func getDevicesRequest() (string, string) {
	return "/home/device_list", 
		`{"getVirtualModel":false,"getHuamiDevices":0}`
}

func getBeaconRequest(did string) (string, string) {
	return "/v2/device/blt_get_beaconkey", 
		fmt.Sprintf(`{"did":"%s","pdid":1}`, did)
}

func doAPIQuery(client *http.Client, country, endpoint, dataParam string, cred *APICred) ([]byte, error) {
	nonce, signature, err := cred.SignRequest(endpoint, dataParam)
	if err != nil {
		return nil, err
	}

	apiFullURL := fmt.Sprintf("%s/%s", getAPIBaseURL(country), endpoint)
	logi("http get %s", apiFullURL)
	req, err := http.NewRequest(http.MethodGet, apiFullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", getUserAgent())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("x-xiaomi-protocal-flag-cli", "PROTOCAL-HTTP2")
	req.Header.Set("Accept-Encoding", "gzip")

	addCommonCookies(req)
	for _, v := range cred.Cookies {
		req.AddCookie(v)
	}
	req.AddCookie(&http.Cookie{Name: "userId", Value: cred.UserID })
	req.AddCookie(&http.Cookie{Name: "serviceToken", Value: cred.ServiceToken })
	req.AddCookie(&http.Cookie{Name: "yetAnotherServiceToken", Value: cred.ServiceToken })
	req.AddCookie(&http.Cookie{Name: "locale", Value: "en_GB" })
	req.AddCookie(&http.Cookie{Name: "timezone", Value: "GMT+02:00" })
	req.AddCookie(&http.Cookie{Name: "is_daylight", Value: "1" })
	req.AddCookie(&http.Cookie{Name: "dst_offset", Value: "3600000" })
	req.AddCookie(&http.Cookie{Name: "channel", Value: "MI_APP_STORE" })

	q := req.URL.Query()
	q.Add("signature", signature)
	q.Add("_nonce", nonce)
	q.Add("data", dataParam)
	req.URL.RawQuery = q.Encode()

	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		logw("server responded with status code %d", response.StatusCode)
	}

	contentBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if debugMode {
		fmt.Fprintf(os.Stdout, "----- api response -----\n")
		fmt.Fprintln(os.Stdout, string(contentBytes))
		fmt.Fprintf(os.Stdout, "----- /api response -----\n")
	}

	jsonResponse, err := parseJSON(contentBytes)
	if err != nil {
		return nil, err
	}
	if message, ok := jsonResponse["message"]; !ok {
		return nil, fmt.Errorf("unexpected response from server")
	} else {
		if message != "ok" {
			return nil, fmt.Errorf("server responded with invalid message: %s", message)
		}
	}

	var innerList string
	if result, ok := jsonResponse["result"]; !ok {
		return nil, fmt.Errorf("no result from query")
	} else {
		listJSON, err := parseJSON([]byte(result))
		if err != nil {
			return nil, err
		}

		if items, ok := listJSON["list"]; !ok {
			return nil, fmt.Errorf("no result.list from server response")
		} else {
			innerList = items
		}
	}

	return []byte(innerList), nil
}

func getAPIBaseURL(country string) string {
	if country == "CN" {
		return "https://api.io.mi.com/app"
	}
	return fmt.Sprintf("https://%s.api.io.mi.com/app", strings.ToLower(country))
}

func logi(format string, a ...interface{}) {
	if !verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "info: " + format + "\n", a...)
}

func logw(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "warn: " + format + "\n", a...)
}
