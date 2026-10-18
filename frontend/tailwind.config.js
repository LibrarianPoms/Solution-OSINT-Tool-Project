/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        "neon-green": "#00ff41",
        "dark-green": "#00cc33",
        "terminal": "#0d0d0d",
        "panel": "#111111",
        "border-green": "#00ff4133",
      },
      fontFamily: {
        mono: ["'Courier New'", "Courier", "monospace"],
      },
      animation: {
        "pulse-green": "pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "blink": "blink 1s step-end infinite",
        "scan": "scan 2s linear infinite",
      },
      keyframes: {
        blink: {
          "0%, 100%": { opacity: 1 },
          "50%": { opacity: 0 },
        },
        scan: {
          "0%": { transform: "translateY(-100%)" },
          "100%": { transform: "translateY(100%)" },
        }
      }
    },
  },
  plugins: [],
}