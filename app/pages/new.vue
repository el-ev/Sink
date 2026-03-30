<script setup>
import { LinkSchema, nanoid } from '@@/schemas/link'
import { toTypedSchema } from '@vee-validate/zod'
import { Shuffle, Sparkles } from 'lucide-vue-next'
import { useForm } from 'vee-validate'
import { toast } from 'vue-sonner'
import { z } from 'zod'

const { t } = useI18n()

const CreateLinkSchema = LinkSchema.pick({
  url: true,
  slug: true,
}).extend({
  optional: LinkSchema.omit({
    id: true,
    url: true,
    slug: true,
    createdAt: true,
    updatedAt: true,
    title: true,
    description: true,
    image: true,
  }).extend({
    expiration: z.coerce.date().optional(),
  }).optional(),
})

const fieldConfig = {
  optional: {
    comment: {
      component: 'textarea',
    },
  },
}

const form = useForm({
  validationSchema: toTypedSchema(CreateLinkSchema),
  initialValues: {
    slug: nanoid()(),
    url: '',
    optional: {
      comment: '',
    },
  },
})

function randomSlug() {
  form.setFieldValue('slug', nanoid()())
}

const aiSlugPending = ref(false)

async function aiSlug() {
  if (!form.values.url)
    return

  aiSlugPending.value = true
  try {
    const response = await useAPI('/api/link/ai', {
      query: {
        url: form.values.url,
      },
    })
    form.setFieldValue('slug', response.slug)
  }
  finally {
    aiSlugPending.value = false
  }
}

async function onSubmit(formData) {
  const link = {
    url: formData.url,
    slug: formData.slug,
    ...(formData.optional || {}),
    expiration: formData.optional?.expiration ? date2unix(formData.optional.expiration, 'end') : undefined,
  }

  const response = await useAPI('/api/link/create', {
    method: 'POST',
    body: link,
  })

  toast(t('links.create_success'))
  return navigateTo(`/dashboard/link?slug=${encodeURIComponent(response.link.slug)}`)
}
</script>

<template>
  <main class="max-w-3xl py-2 mx-auto space-y-6">
    <DashboardBreadcrumb title="New" />

    <Card>
      <CardHeader>
        <CardTitle>{{ $t('links.create') }}</CardTitle>
      </CardHeader>
      <CardContent>
        <AutoForm
          class="space-y-2"
          :schema="CreateLinkSchema"
          :form="form"
          :field-config="fieldConfig"
          @submit="onSubmit"
        >
          <template #slug="slotProps">
            <div class="relative">
              <div class="flex absolute right-0 top-1 space-x-3">
                <Shuffle
                  class="w-4 h-4 cursor-pointer"
                  @click="randomSlug"
                />
                <Sparkles
                  class="w-4 h-4 cursor-pointer"
                  :class="{ 'animate-bounce': aiSlugPending }"
                  @click="aiSlug"
                />
              </div>
              <AutoFormField
                v-bind="slotProps"
              />
            </div>
          </template>
          <div class="flex justify-end">
            <Button type="submit">
              {{ $t('links.create') }}
            </Button>
          </div>
        </AutoForm>
      </CardContent>
    </Card>
  </main>
</template>
