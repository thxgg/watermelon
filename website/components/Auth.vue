<script setup lang="ts">
const tabs = [{
  slot: 'login',
  label: 'Login',
}, {
  slot: 'register',
  label: 'Register',
}]
</script>

<template>
  <UContainer>
    <h1 class="text-5xl font-bold text-purple-500 text-center h-24">
      Watermelon
    </h1>
    <UTabs :items="tabs" class="w-full">
      <template #login>
        <Login />
      </template>
      <template #register>
        <Register />
      </template>
    </UTabs>
  </UContainer>
</template>

<style scoped>

</style>
