<script setup lang="ts">
import type { FormError } from '@nuxthq/ui/dist/runtime/types'

const state = ref({
  email: '',
  username: '',
  password: '',
  confirmPassword: '',
})
const isValid = ref(true)

const emailRules = [
  (v: string) => !!v || 'Email is required',
  (v: string) => /^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(v) || 'Email must be valid',
]
function validateEmail(): FormError[] {
  return emailRules.map((rule) => {
    return {
      path: 'email',
      message: rule(state.value.email),
    }
  }).filter(validation => validation.message !== true) as FormError[]
}

const usernameRules = [
  (v: string) => !!v || 'Username is required',
  (v: string) => v.length >= 3 || 'Username must be at least 3 characters',
  (v: string) => v.length <= 32 || 'Username must be at most 32 characters',
]
function validateUsername(): FormError[] {
  return usernameRules.map((rule) => {
    return {
      path: 'username',
      message: rule(state.value.username),
    }
  }).filter(validation => validation.message !== true) as FormError[]
}

const isAnyPasswordNonEmpty = computed(() => {
  return state.value.password.length > 0 || state.value.confirmPassword.length > 0
})
const showPassword = ref(false)
const passwordFieldType = computed(() => {
  return showPassword.value ? 'text' : 'password'
})
const passwordRules = [
  (v: string) => !!v || 'Password is required',
  (v: string) => v.length >= 8 || 'Password must be at least 8 characters',
  (v: string) => v.length <= 32 || 'Password must be at most 32 characters',
]
function validatePassword(): FormError[] {
  return passwordRules.map((rule) => {
    return {
      path: 'password',
      message: rule(state.value.password),
    }
  }).filter(validation => validation.message !== true) as FormError[]
}

const confirmPasswordRules = [
  (v: string) => !!v || 'Confirm Password is required',
  (v: string) => v === state.value.password || 'Confirm Password must match Password',
]
function validateConfirmPassword(): FormError[] {
  return confirmPasswordRules.map((rule) => {
    return {
      path: 'confirmPassword',
      message: rule(state.value.confirmPassword),
    }
  }).filter(validation => validation.message !== true) as FormError[]
}

function validate(): FormError[] {
  const errors = []
  errors.push(...validateEmail())
  errors.push(...validateUsername())
  errors.push(...validatePassword())
  errors.push(...validateConfirmPassword())
  isValid.value = errors.length === 0
  return errors
}

async function register() {
  console.log('register', state.value)
}
</script>

<template>
  <UCard>
    <UForm :state="state" :validate="validate" :validate-on="['submit']" class="flex flex-col justify-center items-center gap-4" @submit.prevent="register">
      <UFormGroup name="email" label="Email" class="w-full">
        <UInput v-model="state.email" :autofocus="true" icon="i-mdi-email" placeholder="you@email.com" />
      </UFormGroup>
      <UFormGroup name="username" label="Username" class="w-full">
        <UInput v-model="state.username" icon="i-mdi-account" placeholder="jonhdoe" />
      </UFormGroup>
      <UFormGroup name="password" label="Password" class="w-full">
        <UInput
          v-model="state.password" icon="i-mdi-form-textbox-password" :type="passwordFieldType"
          :ui="{ icon: { trailing: { pointer: '' } } }" placeholder="********"
        >
          <template #trailing>
            <UButton
              v-show="isAnyPasswordNonEmpty" color="gray" variant="link" :padded="false"
              :icon="showPassword ? 'i-mdi-eye' : 'i-mdi-eye-off'" @click="
                showPassword = !showPassword"
            />
          </template>
        </UInput>
      </UFormGroup>
      <UFormGroup name="confirmPassword" label="Confirm Password" class="w-full">
        <UInput
          v-model="state.confirmPassword" icon="i-mdi-form-textbox-password" :type="passwordFieldType"
          :ui="{ icon: { trailing: { pointer: '' } } }" placeholder="********"
        >
          <template #trailing>
            <UButton
              v-show="isAnyPasswordNonEmpty" color="gray" variant="link" :padded="false"
              :icon="showPassword ? 'i-mdi-eye' : 'i-mdi-eye-off'" @click="
                showPassword = !showPassword"
            />
          </template>
        </UInput>
      </UFormGroup>
      <UButton block size="lg" type="submit" :disabled="!isValid">
        Register
      </UButton>
    </UForm>
  </UCard>
</template>
