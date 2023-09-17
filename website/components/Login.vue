<script setup lang="ts">
import type { FormError } from '@nuxthq/ui/dist/runtime/types'
import type { Credentials } from '@/types'

const state = ref({
  email: '',
  password: '',
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

const showPassword = ref(false)
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

function validate(): FormError[] {
  const errors = []
  errors.push(...validateEmail())
  errors.push(...validatePassword())
  isValid.value = errors.length === 0
  return errors
}

async function login(credentials: Credentials) {
  const config = useRuntimeConfig()

  const headers = useRequestHeaders(['cookie'])
  await useFetch(`${config.public.api.url}/login`, {
    method: 'POST',
    headers: {
      ...headers,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(credentials),
  })
  await useAsyncData('user', async () => $fetch(`${config.public.api.url}/me`, {
    method: 'GET',
    headers: useRequestHeaders(['cookie']),
  }))
  navigateTo('/')
}
</script>

<template>
  <UCard>
    <UForm :state="state" :validate="validate" :validate-on="['submit']" class="flex flex-col justify-center items-center gap-4" @submit.prevent="login(state)">
      <UFormGroup name="email" label="Email" class="w-full">
        <UInput v-model="state.email" :autofocus="true" icon="i-mdi-email" placeholder="you@email.com" />
      </UFormGroup>
      <UFormGroup name="password" label="Password" class="w-full">
        <UInput
          v-model="state.password" icon="i-mdi-form-textbox-password" :type="showPassword ? 'text' : 'password'"
          :ui="{ icon: { trailing: { pointer: '' } } }" placeholder="********"
        >
          <template #trailing>
            <UButton
              v-show="state.password !== ''" color="gray" variant="link" :padded="false"
              :icon="showPassword ? 'i-mdi-eye' : 'i-mdi-eye-off'" @click="
                showPassword = !showPassword"
            />
          </template>
        </UInput>
      </UFormGroup>
      <UButton block size="lg" type="submit" :disabled="!isValid" icon="i-mdi-login">
        Login
      </UButton>
    </UForm>
  </UCard>
</template>
