package validator

import (
	"reflect"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
)

var Validator = validator.New(validator.WithRequiredStructEnabled())

func Setup() {
	Validator.RegisterCustomTypeFunc(ValidateUUID, uuid.UUID{})
}

// ValidateUUID implements validator.CustomTypeFunc
func ValidateUUID(field reflect.Value) interface{} {
	if valuer, ok := field.Interface().(uuid.UUID); ok {
		return valuer.String()
	}
	return nil
}
