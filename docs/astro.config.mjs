// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import codeTheme from './src/styles/code-theme.json';

// https://astro.build/config
export default defineConfig({
	site: 'https://docs.achrony.me',
	integrations: [
		starlight({
			title: 'Achronyme Docs',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/achronyme/achronyme' },
			],
			defaultLocale: 'root',
			locales: {
				root: { label: 'English', lang: 'en' },
				es: { label: 'Español' },
			},
			customCss: [
				'@fontsource-variable/jetbrains-mono',
				'./src/styles/custom.css',
			],
			expressiveCode: {
				themes: [codeTheme],
			},
			favicon: '/favicon.svg',
			sidebar: [
				{
					label: 'Getting Started',
					items: [
						{ label: 'Introduction', slug: 'getting-started/introduction' },
						{ label: 'Installation', slug: 'getting-started/installation' },
						{ label: 'Hello World', slug: 'getting-started/hello-world' },
					],
				},
				{
					label: 'Language Reference',
					items: [
						{ label: 'Types & Values', slug: 'language/types-and-values' },
						{ label: 'Control Flow', slug: 'language/control-flow' },
						{ label: 'Functions & Closures', slug: 'language/functions-and-closures' },
						{ label: 'Arrays & Collections', slug: 'language/arrays-and-collections' },
						{ label: 'Native Functions', slug: 'language/native-functions' },
						{ label: 'Error Handling', slug: 'language/error-handling' },
					],
				},
				{
					label: 'Circuit Programming',
					items: [
						{ label: 'Overview', slug: 'circuits/overview' },
						{ label: 'Declarations', slug: 'circuits/declarations' },
						{ label: 'Type Annotations', slug: 'circuits/type-annotations' },
						{ label: 'Builtins', slug: 'circuits/builtins' },
						{ label: 'Operators & Costs', slug: 'circuits/operators-and-costs' },
						{ label: 'Functions in Circuits', slug: 'circuits/functions' },
						{ label: 'Control Flow in Circuits', slug: 'circuits/control-flow' },
					],
				},
				{
					label: 'Zero-Knowledge Concepts',
					items: [
						{ label: 'Field Elements', slug: 'zk-concepts/field-elements' },
						{ label: 'R1CS', slug: 'zk-concepts/r1cs' },
						{ label: 'Plonkish', slug: 'zk-concepts/plonkish' },
						{ label: 'Proof Generation', slug: 'zk-concepts/proof-generation' },
					],
				},
				{
					label: 'CLI Reference',
					items: [
						{ label: 'Commands', slug: 'cli/commands' },
						{ label: 'Circuit Options', slug: 'cli/circuit-options' },
					],
				},
				{
					label: 'Architecture',
					items: [
						{ label: 'Pipeline Overview', slug: 'architecture/pipeline' },
						{ label: 'Crate Map', slug: 'architecture/crate-map' },
						{ label: 'IR & Optimization', slug: 'architecture/ir-and-optimization' },
						{ label: 'Backends', slug: 'architecture/backends' },
						{ label: 'Witness Generation', slug: 'architecture/witness-generation' },
						{ label: 'Extension Guide', slug: 'architecture/extension-guide' },
						{ label: 'VM & Bytecode', slug: 'architecture/vm-and-bytecode' },
						{ label: 'Memory & GC', slug: 'architecture/memory-and-gc' },
					],
				},
				{
					label: 'Tutorials',
					items: [
						{ label: 'Merkle Membership Proof', slug: 'tutorials/merkle-proof' },
						{ label: 'Inline Proofs', slug: 'tutorials/inline-proofs' },
						{ label: 'Poseidon Hashing', slug: 'tutorials/poseidon-hashing' },
						{ label: 'BigInt Arithmetic', slug: 'tutorials/bigint-arithmetic' },
					],
				},
			],
		}),
	],
});
