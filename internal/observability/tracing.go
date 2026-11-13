package observability

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func SetupTracing(ctx context.Context, serviceName, environment, endpoint string) (trace.TracerProvider, func(context.Context) error, error) {
	if strings.TrimSpace(serviceName) == "" {
		serviceName = "provisioning"
	}
	if strings.TrimSpace(endpoint) == "" {
		provider := otel.GetTracerProvider()
		return provider, func(context.Context) error { return nil }, nil
	}
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		if err == nil {
			err = fmt.Errorf("OTLP traces endpoint must be an absolute HTTP(S) URL")
		}
		return nil, nil, err
	}
	options := []otlptracehttp.Option{otlptracehttp.WithEndpoint(parsed.Host)}
	if parsed.Path != "" && parsed.Path != "/" {
		options = append(options, otlptracehttp.WithURLPath(parsed.Path))
	}
	if parsed.Scheme == "http" {
		options = append(options, otlptracehttp.WithInsecure())
	}
	exporter, err := otlptracehttp.New(ctx, options...)
	if err != nil {
		return nil, nil, err
	}
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes("https://opentelemetry.io/schemas/1.26.0", attribute.String("service.name", serviceName), attribute.String("deployment.environment.name", environment)))
	if err != nil {
		return nil, nil, err
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	otel.SetTracerProvider(provider)
	return provider, provider.Shutdown, nil
}
