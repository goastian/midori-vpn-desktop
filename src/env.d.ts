// CSS module declarations
declare module '*.css' {
  const content: Record<string, string>
  export default content
}

declare module '*.png' {
  const src: string
  export default src
}

declare module '*.svg' {
  const src: string
  export default src
}

declare const __APP_VERSION__: string
