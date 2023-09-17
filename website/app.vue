<script setup lang="ts">
import { isAuthenticated } from '@/utils/auth'
</script>

<template>
  <div class="w-screen h-screen flex items-center gap-4 p-4">
    <TheSidebar v-if="isAuthenticated()" class="h-full" />
    <NuxtPage class="h-full w-full" />
    <UNotifications />
  </div>
</template>
