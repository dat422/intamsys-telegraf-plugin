type intamsys struct {
	// Existing fields...
	URLs            []string `toml:"urls"`
	Method          string   `toml:"method"`
	Body            string   `toml:"body"`
	ContentEncoding string   `toml:"content_encoding"`

	// Basic authentication
	Username config.Secret `toml:"username"`
	Password config.Secret `toml:"password"`

	// Bearer authentication
	BearerToken string        `toml:"bearer_token" deprecated:"1.28.0;1.35.0;use 'token_file' instead"`
	Token       config.Secret `toml:"token"`
	TokenFile   string        `toml:"token_file"`

	Headers            map[string]*config.Secret `toml:"headers"`
	SuccessStatusCodes []int                     `toml:"success_status_codes"`
	QueryToken         config.Secret            `toml:"query_token"` // New field for query token
	Log                telegraf.Logger           `toml:"-"`

	common_http.HTTPClientConfig

	client     *http.Client
	parserFunc telegraf.ParserFunc
}

func (h *intamsys) gatherURL(acc telegraf.Accumulator, url string) error {
	// Append the query token if it's specified
	if h.QueryToken != nil {
		queryToken, err := h.QueryToken.Get()
		if err != nil {
			return fmt.Errorf("getting query token failed: %w", err)
		}
		defer queryToken.Destroy()

		// Parse the URL and append the query token
		if strings.Contains(url, "?") {
			url += "&token=" + queryToken.String()
		} else {
			url += "?token=" + queryToken.String()
		}
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
