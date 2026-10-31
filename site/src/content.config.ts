import { defineCollection } from 'astro:content';
import { docsLoader, i18nLoader } from '@astrojs/starlight/loaders';
import { docsSchema, i18nSchema } from '@astrojs/starlight/schema';

export const loader = docsLoader();
export const schema = docsSchema();
export const collections = { docs: defineCollection({ loader, schema }), i18n: defineCollection({ loader: i18nLoader(), schema: i18nSchema() }) };
