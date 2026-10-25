/**
 * Centralized Branding Configuration for VANTA
 * 
 * Keep public-facing branding configurable across the website,
 * while technical and repository references remain Graph_Z3.
 */

export const BRAND = {
  // Public Product Identity
  name: 'VANTA',
  wordmark: 'VANTA',
  tagline: 'See what hides beneath the binary.',
  version: '',

  // Cinematic Hero Copy (matches exact prompt requirements)
  heroHeadline: 'Is your code protected from every hacker?',
  supportingHeadline: 'Bridge Deep Graph Intelligence with Rigorous Symbolic Solving.',
  subheadline:
    'Combine Graph Neural Networks and Z3 constraint solving to outsmart complex binaries, triage risk, and find hidden vulnerabilities without the state explosion.',

  // Product Introduction
  productIntroHeadline: 'See beyond the binary.',
  productIntroSubtext:
    'Connect structural intelligence with symbolic reasoning to investigate complex program behavior.',

  // Final Call to Action
  finalCtaHeadline: 'Your next binary is waiting.',
  finalCtaSubtext:
    'Bring your binary into VANTA and explore what its structure can reveal.',

  // Technical & Repository Identifiers
  technicalName: 'Graph_Z3',
  githubUrl: 'https://github.com/sandy191020/graph_z3',
  license: 'Research & Verification Framework',
} as const;
