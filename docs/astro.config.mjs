// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import codeTheme from './src/styles/code-theme.json';
import achGrammar from './src/styles/achronyme.tmLanguage.json';

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
				shiki: {
					langs: [
						{ ...achGrammar, name: 'ach', aliases: ['achronyme'] },
					],
				},
			},
			favicon: '/favicon.svg',
			sidebar: [
				{
					label: 'Getting Started',
					translations: { es: 'Primeros Pasos' },
					items: [
						{ label: 'Introduction', slug: 'getting-started/introduction', translations: { es: 'Introducción' } },
						{ label: 'Installation', slug: 'getting-started/installation', translations: { es: 'Instalación' } },
						{ label: 'Hello World', slug: 'getting-started/hello-world', translations: { es: 'Hola Mundo' } },
					{ label: 'Editor Setup', slug: 'getting-started/editor-setup', translations: { es: 'Configuración del Editor' } },
					],
				},
				{
					label: 'Language Reference',
					translations: { es: 'Referencia del Lenguaje' },
					items: [
						{ label: 'Types & Values', slug: 'language/types-and-values', translations: { es: 'Tipos y Valores' } },
						{ label: 'Control Flow', slug: 'language/control-flow', translations: { es: 'Flujo de Control' } },
						{ label: 'Functions & Closures', slug: 'language/functions-and-closures', translations: { es: 'Funciones y Closures' } },
						{ label: 'Arrays & Collections', slug: 'language/arrays-and-collections', translations: { es: 'Arrays y Colecciones' } },
						{ label: 'Native Functions', slug: 'language/native-functions', translations: { es: 'Funciones Nativas' } },
						{ label: 'Error Handling', slug: 'language/error-handling', translations: { es: 'Manejo de Errores' } },
						{ label: 'Modules', slug: 'language/modules', translations: { es: 'Módulos' } },
					],
				},
				{
					label: 'Circuit Programming',
					translations: { es: 'Programación de Circuitos' },
					items: [
						{ label: 'Overview', slug: 'circuits/overview', translations: { es: 'Descripción General' } },
						{ label: 'Declarations', slug: 'circuits/declarations', translations: { es: 'Declaraciones' } },
						{ label: 'Type Annotations', slug: 'circuits/type-annotations', translations: { es: 'Anotaciones de Tipo' } },
						{ label: 'Builtins', slug: 'circuits/builtins', translations: { es: 'Funciones Integradas' } },
						{ label: 'Operators & Costs', slug: 'circuits/operators-and-costs', translations: { es: 'Operadores y Costos' } },
						{ label: 'Functions in Circuits', slug: 'circuits/functions', translations: { es: 'Funciones en Circuitos' } },
						{ label: 'Control Flow in Circuits', slug: 'circuits/control-flow', translations: { es: 'Flujo de Control en Circuitos' } },
					],
				},
				{
					label: 'Zero-Knowledge Concepts',
					translations: { es: 'Conceptos de Conocimiento Cero' },
					items: [
						{ label: 'Field Elements', slug: 'zk-concepts/field-elements', translations: { es: 'Elementos de Campo' } },
						{ label: 'R1CS', slug: 'zk-concepts/r1cs' },
						{ label: 'Plonkish', slug: 'zk-concepts/plonkish' },
						{ label: 'Proof Generation', slug: 'zk-concepts/proof-generation', translations: { es: 'Generación de Pruebas' } },
					],
				},
				{
					label: 'CLI Reference',
					translations: { es: 'Referencia del CLI' },
					items: [
						{ label: 'Commands', slug: 'cli/commands', translations: { es: 'Comandos' } },
						{ label: 'Circuit Options', slug: 'cli/circuit-options', translations: { es: 'Opciones de Circuito' } },
					],
				},
				{
					label: 'Architecture',
					translations: { es: 'Arquitectura' },
					items: [
						{ label: 'Pipeline Overview', slug: 'architecture/pipeline', translations: { es: 'Visión General del Pipeline' } },
						{ label: 'Crate Map', slug: 'architecture/crate-map', translations: { es: 'Mapa de Crates' } },
						{ label: 'IR & Optimization', slug: 'architecture/ir-and-optimization', translations: { es: 'IR y Optimización' } },
						{ label: 'Backends', slug: 'architecture/backends' },
						{ label: 'Witness Generation', slug: 'architecture/witness-generation', translations: { es: 'Generación de Testigos' } },
						{ label: 'Extension Guide', slug: 'architecture/extension-guide', translations: { es: 'Guía de Extensión' } },
						{ label: 'VM & Bytecode', slug: 'architecture/vm-and-bytecode', translations: { es: 'VM y Bytecode' } },
						{ label: 'Memory & GC', slug: 'architecture/memory-and-gc', translations: { es: 'Memoria y GC' } },
					],
				},
				{
					label: 'Tutorials',
					translations: { es: 'Tutoriales' },
					items: [
						{ label: 'Merkle Membership Proof', slug: 'tutorials/merkle-proof', translations: { es: 'Prueba de Membresía Merkle' } },
						{ label: 'Inline Proofs', slug: 'tutorials/inline-proofs', translations: { es: 'Pruebas en Línea' } },
						{ label: 'Poseidon Hashing', slug: 'tutorials/poseidon-hashing', translations: { es: 'Hashing Poseidon' } },
						{ label: 'BigInt Arithmetic', slug: 'tutorials/bigint-arithmetic', translations: { es: 'Aritmética BigInt' } },
					{ label: 'Secret Voting', slug: 'tutorials/secret-voting', translations: { es: 'Votación Secreta' } },
					],
				},
			],
		}),
	],
});
