<script setup lang="ts">
import type { VerticalNavigationLink } from '@nuxthq/ui/dist/runtime/types'

const isExpanded = ref(false)

const links: VerticalNavigationLink[] = [
  {
    label: 'Users',
    icon: 'i-mdi-account-group',
    to: '/users',
  },
]
const expandableLinks: ComputedRef<VerticalNavigationLink[]> = computed(() => {
  if (isExpanded.value) {
    return links
  }
  else {
    return links.map((link) => {
      return {
        ...link,
        label: '',
      }
    })
  }
})

async function logout() {
  const config = useRuntimeConfig()

  await $fetch(`${config.public.api.url}/logout`, {
    method: 'DELETE',
  })
  navigateTo('/auth')
}
</script>

<template>
  <div class="flex gap-1">
    <UCard as="aside" :ui="{ body: { base: 'flex-grow', padding: 'px-2 py-3 sm:p-4' }, header: { padding: 'px-2 py-3 sm:p-4' }, footer: { padding: 'px-2 py-3 sm:p-4' } }" class="flex flex-col">
      <template #header>
        <header>
          <h1 class="text-center">
            {{ isExpanded ? 'Watermelon' : 'WM' }}
          </h1>
        </header>
      </template>
      <nav class="h-full flex flex-col justify-between">
        <UVerticalNavigation :links="expandableLinks" :ui="{ icon: { base: 'flex-shrink-0 w-5 h-5 leading-5' }, base: 'group relative flex items-center gap-2 focus:outline-none focus-visible:outline-none dark:focus-visible:outline-none focus-visible:before:ring-inset focus-visible:before:ring-1 focus-visible:before:ring-primary-500 dark:focus-visible:before:ring-primary-400 before:absolute before:inset-px before:rounded-md disabled:cursor-not-allowed disabled:opacity-75 justify-center' }" />
        <UButton block variant="ghost" icon="i-mdi-account-circle" to="/profile">
          {{ isExpanded ? 'Profile' : '' }}
        </UButton>
      </nav>
      <template #footer>
        <footer class="text-center">
          <UButton block variant="outline" icon="i-mdi-logout" @click="logout">
            {{ isExpanded ? 'Logout' : '' }}
          </UButton>
        </footer>
      </template>
    </UCard>
    <UButton :icon="isExpanded ? 'i-mdi-arrow-expand-left' : 'i-mdi-arrow-expand-right'" size="xs" variant="link" @click="isExpanded = !isExpanded" />
  </div>
</template>
