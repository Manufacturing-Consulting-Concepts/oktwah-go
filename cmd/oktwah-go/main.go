package main

/*
This program is used to pull in Okta system logs and send them to Wazuh.  This will be accomplished
by using the Okta API to pull in the logs and then send them to a log file where Wazuh will be able
pull them into the Wazuh server.

CODEOWNER: @mockingjay (DavidHoenisch)
Org: MFG Consulting Concepts
Date: 2022-11-28
Version 0.0.1

Made with the help of our AI overlord, Copilot =).

*/
import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/viper"
)

/*
global variable that contains now time minus 5 minutes in UTC format.
*/
var nowMinus5 = time.Now().UTC().Add(-5 * time.Minute).Format("2006-01-02T15:04:05.000Z")

// Create structure for Okta system logs.
type OktaSystemLog struct {
	Uuid            string `json:"uuid"`
	Published       string `json:"published"`
	EventType       string `json:"eventType"`
	Version         string `json:"version"`
	Severity        string `json:"severity"`
	LegacyEventType string `json:"legacyEventType"`
	DisplayMessage  string `json:"displayMessage"`
	Actor           struct {
		Id          string `json:"id"`
		Type        string `json:"type"`
		AlternateId string `json:"alternateId"`
		DisplayName string `json:"displayName"`
		DetailEntry string `json:"detailEntry"`
	} `json:"actor"`
	Client struct {
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
			Os           string `json:"os"`
			Browser      string `json:"browser"`
		} `json:"userAgent"`
		GeographicalContext struct {
			Geolocation struct {
				Lat float32 `json:"lat"`
				Lon float32 `json:"lon"`
			} `json:"geolocation"`
			City       string `json:"city"`
			State      string `json:"state"`
			Country    string `json:"country"`
			PostalCode string `json:"postalCode"`
		} `json:"geographicalContext"`
		Zone      string `json:"zone"`
		IpAddress string `json:"ipAddress"`
		Device    string `json:"device"`
		Id        string `json:"id"`
	} `json:"client"`
	Outcome struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	} `json:"outcome"`
	Target []struct {
		Id          string `json:"id"`
		Type        string `json:"type"`
		AlternateId string `json:"alternateId"`
		DisplayName string `json:"displayName"`
		DetailEntry string `json:"detailEntry"`
	} `json:"target"`
	Transaction struct {
		Id     string   `json:"id"`
		Type   string   `json:"type"`
		Detail struct{} `json:"detail"`
	} `json:"transaction"`
	AuthenticationContext struct {
		AuthenticationProvider string `json:"authenticationProvider"`
		CredentialProvider     string `json:"credentialProvider"`
		CredentialType         string `json:"credentialType"`
		Issuer                 struct {
			Id   string `json:"id"`
			Type string `json:"type"`
		} `json:"issuer"`
		ExternalSessionId string `json:"externalSessionId"`
		Interface         string `json:"interface"`
	} `json:"authenticationContext"`
	SecurityContext struct {
		AsNumber int    `json:"asNumber"`
		AsOrg    string `json:"asOrg"`
		Isp      string `json:"isp"`
		Domain   string `json:"domain"`
		IsProxy  bool   `json:"isProxy"`
	} `json:"securityContext"`
	Request struct {
		IpChain []struct {
			Ip                  string `json:"ip"`
			GeographicalContext struct {
				Geolocation struct {
					Lat float32 `json:"lat"`
					Lon float32 `json:"lon"`
				} `json:"geolocation"`
				City       string `json:"city"`
				State      string `json:"state"`
				Country    string `json:"country"`
				PostalCode string `json:"postalCode"`
			} `json:"geographicalContext"`
			Version string `json:"version"`
			Source  string `json:"source"`
		} `json:"ipChain"`
	} `json:"request"`
}

// Function that will take in application log messages and send them to the log file.
func logMessage(message string) {
	logFile, err := os.OpenFile("oktwah.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger := log.New(logFile, "", log.LstdFlags)
	logger.Println(message)
}

// Function that check that the Okta application log file exists.
func checkOktaSystemLogFile() {
	_, err := os.Stat("okta-system.log")
	if os.IsNotExist(err) {
		logMessage("Okta system log file does not exist.  Creating now.")
		os.Create("okta-system.log")
	} else {
		logMessage("Okta system log file exists.")
	}
}

// Function that will take in the Okta system log data and write it to the log file.
func writeOktaSystemLogData(oktaSystemLogs OktaSystemLog) {
	logFile, err := os.OpenFile("okta-system.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	logger := log.New(logFile, "", log.LstdFlags)
	logger.Println(oktaSystemLogs)
}

// Function that get log events from Okta API
func getOktaSystemLogs() {
	logMessage("Getting Okta system logs.")

	// Get Okta API token from config file.
	viper.SetConfigFile(".env")
	err := viper.ReadInConfig()
	if err != nil {
		logMessage("Error reading config file.")
	}

	// Set vars from config file.
	oktaApiToken := viper.GetString("api")
	oktaUrl := viper.GetString("url") + nowMinus5

	// Create request to Okta API.
	req, err := http.NewRequest(http.MethodGet, oktaUrl, nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "SSWS "+oktaApiToken)

	if err != nil {
		logMessage("Error creating new request.")
		os.Exit(1)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logMessage("Error sending request to Okta API")
		os.Exit(1)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		logMessage("Error reading response body.")
		os.Exit(1)
	}

	// Unmarshal response body into struct.
	var oktaSystemLogs []OktaSystemLog
	err = json.Unmarshal(resBody, &oktaSystemLogs)
	if err != nil {
		logMessage("Error unmarshalling response body.")
		fmt.Println(err)
		os.Exit(1)
	}
	// Loop through Okta system logs and write them to the log file.
	for _, log := range oktaSystemLogs {
		writeOktaSystemLogData(log)
	}
}

// ------------------ MAIN ------------------
func main() {
	logMessage("Starting Okta to Wazuh application.")
	checkOktaSystemLogFile()

	for {
		getOktaSystemLogs()
		time.Sleep(5 * time.Minute)
	}
}

// ------------------ END MAIN ------------------
