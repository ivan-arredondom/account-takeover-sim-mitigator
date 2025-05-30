/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
    "./public/index.html",
  ],
  theme: {
    extend: {
      colors: {
        primary: {
          50: '#eff6ff',
          100: '#dbeafe',
          200: '#bfdbfe',
          300: '#93c5fd',
          400: '#60a5fa',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          800: '#1e40af',
          900: '#1e3a8a',
          950: '#172554',
        },
        security: {
          low: '#10b981',      // Green for low risk
          medium: '#f59e0b',   // Yellow for medium risk
          high: '#ef4444',     // Red for high risk
          critical: '#991b1b', // Dark red for critical
        },
        status: {
          online: '#10b981',
          warning: '#f59e0b',
          error: '#ef4444',
          offline: '#6b7280',
        }
      },
      fontFamily: {
        sans: [
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif',
        ],
        mono: [
          '"SF Mono"',
          'Monaco',
          'Inconsolata',
          '"Roboto Mono"',
          '"Source Code Pro"',
          'monospace',
        ],
      },
      fontSize: {
        '2xs': ['0.625rem', { lineHeight: '0.75rem' }],
      },
      spacing: {
        '18': '4.5rem',
        '88': '22rem',
        '128': '32rem',
      },
      borderRadius: {
        '4xl': '2rem',
      },
      boxShadow: {
        'inner-lg': 'inset 0 10px 15px -3px rgba(0, 0, 0, 0.1), inset 0 4px 6px -2px rgba(0, 0, 0, 0.05)',
        'neumorphism': '20px 20px 60px #d1d5db, -20px -20px 60px #ffffff',
        'security': '0 4px 14px 0 rgba(59, 130, 246, 0.1)',
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-in-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'bounce-in': 'bounceIn 0.5s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 3s linear infinite',
        'ping-slow': 'ping 3s cubic-bezier(0, 0, 0.2, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateY(-10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        bounceIn: {
          '0%': { transform: 'scale(0.3)', opacity: '0' },
          '50%': { transform: 'scale(1.05)' },
          '70%': { transform: 'scale(0.9)' },
          '100%': { transform: 'scale(1)', opacity: '1' },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
      screens: {
        'xs': '475px',
        '3xl': '1600px',
      },
      zIndex: {
        '60': '60',
        '70': '70',
        '80': '80',
        '90': '90',
        '100': '100',
      },
      maxWidth: {
        '8xl': '88rem',
        '9xl': '96rem',
      },
    },
  },
  plugins: [
    require('@tailwindcss/forms')({
      strategy: 'class', // only generate classes
    }),
    // Custom plugin for security-specific utilities
    function({ addUtilities, addComponents, theme }) {
      const newUtilities = {
        '.text-security-low': {
          color: theme('colors.security.low'),
        },
        '.text-security-medium': {
          color: theme('colors.security.medium'),
        },
        '.text-security-high': {
          color: theme('colors.security.high'),
        },
        '.text-security-critical': {
          color: theme('colors.security.critical'),
        },
        '.bg-security-low': {
          backgroundColor: theme('colors.security.low'),
        },
        '.bg-security-medium': {
          backgroundColor: theme('colors.security.medium'),
        },
        '.bg-security-high': {
          backgroundColor: theme('colors.security.high'),
        },
        '.bg-security-critical': {
          backgroundColor: theme('colors.security.critical'),
        },
        '.gradient-security': {
          background: `linear-gradient(135deg, ${theme('colors.primary.500')}, ${theme('colors.primary.700')})`,
        },
        '.scrollbar-hide': {
          '-ms-overflow-style': 'none',
          'scrollbar-width': 'none',
          '&::-webkit-scrollbar': {
            display: 'none',
          },
        },
        '.scrollbar-thin': {
          'scrollbar-width': 'thin',
          'scrollbar-color': `${theme('colors.gray.400')} ${theme('colors.gray.200')}`,
          '&::-webkit-scrollbar': {
            width: '6px',
            height: '6px',
          },
          '&::-webkit-scrollbar-track': {
            background: theme('colors.gray.200'),
            borderRadius: '3px',
          },
          '&::-webkit-scrollbar-thumb': {
            background: theme('colors.gray.400'),
            borderRadius: '3px',
            '&:hover': {
              background: theme('colors.gray.500'),
            },
          },
        },
      }

      const newComponents = {
        '.card-security': {
          backgroundColor: theme('colors.white'),
          borderRadius: theme('borderRadius.lg'),
          boxShadow: theme('boxShadow.security'),
          border: `1px solid ${theme('colors.gray.200')}`,
          transition: 'all 0.2s ease-in-out',
          '&:hover': {
            transform: 'translateY(-2px)',
            boxShadow: theme('boxShadow.xl'),
          },
        },
        '.status-indicator': {
          display: 'inline-flex',
          alignItems: 'center',
          padding: `${theme('spacing.1')} ${theme('spacing.2')}`,
          borderRadius: theme('borderRadius.full'),
          fontSize: theme('fontSize.xs[0]'),
          fontWeight: theme('fontWeight.medium'),
          '&.online': {
            backgroundColor: theme('colors.green.100'),
            color: theme('colors.green.800'),
          },
          '&.warning': {
            backgroundColor: theme('colors.yellow.100'),
            color: theme('colors.yellow.800'),
          },
          '&.error': {
            backgroundColor: theme('colors.red.100'),
            color: theme('colors.red.800'),
          },
          '&.offline': {
            backgroundColor: theme('colors.gray.100'),
            color: theme('colors.gray.800'),
          },
        },
        '.risk-badge': {
          display: 'inline-flex',
          alignItems: 'center',
          padding: `${theme('spacing.1')} ${theme('spacing.2')}`,
          borderRadius: theme('borderRadius.full'),
          fontSize: theme('fontSize.xs[0]'),
          fontWeight: theme('fontWeight.medium'),
          '&.low': {
            backgroundColor: theme('colors.green.100'),
            color: theme('colors.green.800'),
          },
          '&.medium': {
            backgroundColor: theme('colors.yellow.100'),
            color: theme('colors.yellow.800'),
          },
          '&.high': {
            backgroundColor: theme('colors.red.100'),
            color: theme('colors.red.800'),
          },
          '&.critical': {
            backgroundColor: theme('colors.red.200'),
            color: theme('colors.red.900'),
          },
        },
      }

      addUtilities(newUtilities)
      addComponents(newComponents)
    },
  ],
  // Enable dark mode support
  darkMode: 'class',
  // Optimize for production
  corePlugins: {
    preflight: true,
  },
}