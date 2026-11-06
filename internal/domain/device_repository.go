package domain

import "context"

// DeviceRepository persists the device-registry aggregate without exposing
// storage-specific details to services and orchestration code.
type DeviceRepository interface {
	Create(context.Context, Device) error
	Get(context.Context, string) (Device, error)
	Save(context.Context, Device) error
}
