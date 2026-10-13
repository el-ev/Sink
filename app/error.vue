<script setup>
const props = defineProps({
  error: Object,
})

const statusCode = computed(() => props.error?.statusCode || 404)
const message = computed(() => statusCode.value === 404 ? 'Page Not Found' : (props.error?.statusMessage || 'Something went wrong'))

useHead({
  title: computed(() => `${statusCode.value} - ${message.value}`),
})
</script>

<template>
  <main class="flex flex-col items-center justify-center min-h-screen gap-4 p-4 text-center">
    <h1 class="text-6xl font-bold">
      {{ statusCode }}
    </h1>
    <p class="text-lg text-muted-foreground">
      {{ message }}
    </p>
    <a href="/" class="underline underline-offset-4">Go home</a>
  </main>
</template>
