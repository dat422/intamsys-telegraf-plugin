//go:generate ../../../tools/config_includer/generator
//go:generate ../../../tools/readme_config_includer/generator
package intamsys

import (
	"compress/gzip"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	common_http "github.com/influxdata/telegraf/plugins/common/http"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

var once sync.Once

const noMetricsCreatedMsg = "no metrics were created"

type intamsys struct {
	URLs            []string toml:"urls"
	Method          string   toml:"method"
	Body            string   toml:"body"
	ContentEncoding string   toml:"content_encoding"

	// Query parameter from secret
	QueryToken config.Secret toml:"query_token"
	QueryKey   string        toml:"query_key"

	// Basic authentication
	Username config.Secret toml:"username"
	Password config.Secret toml:"password"

	// Bearer authentication
	BearerToken string        toml:"bearer_token" deprecated:"1.28.0;1.35.0;use 'token_file' instead"
	Token       config.Secret toml:"token"
	TokenFile   string        toml:"token_file"

	Headers            map[string]*config.Secret toml:"headers"
	SuccessStatusCodes []int                     toml:"success_status_codes"
	Log                telegraf.Logger           toml:"-"

	common_http.HTTPClientConfig

	client     *http.Client
	parserFunc telegraf.ParserFunc
}

func (*intamsys) SampleConfig() string {
	return sampleConfig
}

func (h *intamsys) Init() error {
	// For backward compatibility
	if h.TokenFile != "" && h.BearerToken != "" && h.TokenFile != h.BearerToken {
		return errors.New("conflicting settings for 'bearer_token' and 'token_file'")
	} else if h.TokenFile == "" && h.BearerToken != "" {
		h.TokenFile = h.BearerToken
	}

	// We cannot use multiple sources for tokens
	if h.TokenFile != "" && !h.Token.Empty() {
		return errors.New("either use 'token_file' or 'token' not both")
	}

	// Validate query token configuration
	if !h.QueryToken.Empty() && h.QueryKey == "" {
		return errors.New("query_key must be set when query_token is provided")
	}

	// Create the client
	ctx := context.Background()
	client, err := h.HTTPClientConfig.CreateClient(ctx, h.Log)
	if err != nil {
		return err
	}
	h.client = client

	// Set default as [200]
	if len(h.SuccessStatusCodes) == 0 {
		h.SuccessStatusCodes = []int{200}
	}
	return nil
}

func (h *intamsys) SetParserFunc(fn telegraf.ParserFunc) {
	h.parserFunc = fn
}

func (h *intamsys) Start(_ telegraf.Accumulator) error {
	return nil
}

func (h *intamsys) Gather(acc telegraf.Accumulator) error {
	var wg sync.WaitGroup
	for _, u := range h.URLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if err := h.gatherURL(acc, url); err != nil {
				acc.AddError(fmt.Errorf("[url=%s]: %w", url, err))
			}
		}(u)
	}

	wg.Wait()

	return nil
}

func (h *intamsys) Stop() {
	if h.client != nil {
		h.client.CloseIdleConnections()
	}
}

// Prepares the URL with optional query parameter from secret
func (h *intamsys) prepareURL(originalURL string) (string, error) {
	// Parse the original URL
	parsedURL, err := url.Parse(originalURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	// If query token and key are set, add the query parameter
	if !h.QueryToken.Empty() {
		// Get the token value
		tokenSecret, err := h.QueryToken.Get()
		if err != nil {
			return "", fmt.Errorf("failed to get query token: %w", err)
		}
		defer tokenSecret.Destroy()

		// DEBUGGING: Print the query token to stdout
		fmt.Printf("DEBUG: Query Token Retrieved: %s\n", tokenSecret.String())

		// Get query parameters
		query := parsedURL.Query()
		
		// Add or replace the query parameter
		query.Set(h.QueryKey, tokenSecret.String())
		
		// Update the URL's RawQuery
		parsedURL.RawQuery = query.Encode()
	}

	return parsedURL.String(), nil
}

// Gathers data from a particular URL
func (h *intamsys) gatherURL(acc telegraf.Accumulator, originalURL string) error {
	// Prepare URL with potential query parameter
	url, err := h.prepareURL(originalURL)
	if err != nil {
		return err
	}

	body := makeRequestBodyReader(h.ContentEncoding, h.Body)
	request, err := http.NewRequest(h.Method, url, body)
	if err != nil {
		return err
	}

	if !h.Token.Empty() {
		token, err := h.Token.Get()
		if err != nil {
			return err
		}
		bearer := "Bearer " + strings.TrimSpace(token.String())
		token.Destroy()
		request.Header.Set("Authorization", bearer)
	} else if h.TokenFile != "" {
		token, err := os.ReadFile(h.TokenFile)
		if err != nil {
			return err
		}
		bearer := "Bearer " + strings.Trim(string(token), "\n")
		request.Header.Set("Authorization", bearer)
	}

	if h.ContentEncoding == "gzip" {
		request.Header.Set("Content-Encoding", "gzip")
	}

	for k, v := range h.Headers {
		secret, err := v.Get()
		if err != nil {
			return err
		}

		headerVal := secret.String()
		if strings.EqualFold(k, "host") {
			request.Host = headerVal
		} else {
			request.Header.Add(k, headerVal)
		}

		secret.Destroy()
	}

	if err := h.setRequestAuth(request); err != nil {
		return err
	}

	resp, err := h.client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseHasSuccessCode := false
	for _, statusCode := range h.SuccessStatusCodes {
		if resp.StatusCode == statusCode {
			responseHasSuccessCode = true
			break
		}
	}

	if !responseHasSuccessCode {
		return fmt.Errorf("received status code %d (%s), expected any value out of %v",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
			h.SuccessStatusCodes)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading body failed: %w", err)
	}

	// Instantiate a new parser for the new data to avoid trouble with stateful parsers
	parser, err := h.parserFunc()
	if err != nil {
		return fmt.Errorf("instantiating parser failed: %w", err)
	}
	metrics, err := parser.Parse(b)
	if err != nil {
		return fmt.Errorf("parsing metrics failed: %w", err)
	}

	if len(metrics) == 0 {
		once.Do(func() {
			h.Log.Debug(noMetricsCreatedMsg)
		})
	}

	for _, metric := range metrics {
		if !metric.HasTag("url") {
			metric.AddTag("url", url)
		}
		acc.AddFields(metric.Name(), metric.Fields(), metric.Tags(), metric.Time())
	}

	return nil
}

// ... (rest of the existing code remains the same)

func init() {
	inputs.Add("intamsys", func() telegraf.Input {
		return &intamsys{
			Method: "GET",
		}
	})
}