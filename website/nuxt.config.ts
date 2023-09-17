// https://nuxt.com/docs/api/configuration/nuxt-config
export default defineNuxtConfig({
  devtools: { enabled: true },
  pages: true,
  modules: ['@nuxtjs/eslint-module', '@nuxthq/ui'],
  eslint: {
    failOnError: true,
  },
  ui: {
    icons: ['mdi'],
  },
  runtimeConfig: {
    public: {
      api: {
        url: '',
      },
    },
  },
})
