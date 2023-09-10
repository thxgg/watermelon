package validator

import (
	"reflect"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

func New() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	v.RegisterCustomTypeFunc(validateUUID, uuid.UUID{})
	return v
}

// validateUUID implements validator.CustomTypeFunc
func validateUUID(field reflect.Value) interface{} {
	if valuer, ok := field.Interface().(uuid.UUID); ok {
		return valuer.String()
	}
	return nil
}
