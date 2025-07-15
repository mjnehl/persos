# Aura Design System

## Introduction

The Aura Design System is a comprehensive set of design standards, components, and guidelines that ensure consistency and quality across all Aura interfaces. This system evolves through four implementation phases, growing from basic UI elements to sophisticated AI-driven interactions.

## Design Tokens

### Color System

#### Primary Palette
```css
/* Brand Colors */
--aura-primary-900: #1a2051;    /* Darkest - Headers */
--aura-primary-800: #1e2666;
--aura-primary-700: #232c7a;
--aura-primary-600: #28338f;    /* Main brand color */
--aura-primary-500: #2E3A87;    /* Default primary */
--aura-primary-400: #4a52a3;
--aura-primary-300: #666ebf;
--aura-primary-200: #999fd6;
--aura-primary-100: #cccfec;
--aura-primary-50:  #e6e7f5;

/* AI/Intelligence Colors */
--aura-intelligence-600: #5941d8;
--aura-intelligence-500: #6C5CE7;  /* Default AI color */
--aura-intelligence-400: #8577eb;
--aura-intelligence-300: #9e92ef;
--aura-intelligence-200: #c6bff7;
--aura-intelligence-100: #e3dffb;

/* Action Colors */
--aura-action-600: #00a8a8;
--aura-action-500: #00CEC9;     /* Default action */
--aura-action-400: #1ad6d1;
--aura-action-300: #4ddeda;
--aura-action-200: #80e7e3;
--aura-action-100: #b3efec;
```

#### Semantic Colors
```css
/* Status Colors */
--aura-success: #00b894;
--aura-warning: #FDCB6E;
--aura-error: #FF6B6B;
--aura-info: #74b9ff;

/* Neutral Colors */
--aura-gray-900: #2D3436;
--aura-gray-800: #383e42;
--aura-gray-700: #4a5155;
--aura-gray-600: #636e72;
--aura-gray-500: #95a5a6;
--aura-gray-400: #b2bec3;
--aura-gray-300: #d1d8dc;
--aura-gray-200: #e9ecef;
--aura-gray-100: #f5f6fa;
--aura-gray-50:  #fafbfc;
```

### Typography Scale

```css
/* Font Families */
--font-primary: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
--font-mono: 'JetBrains Mono', 'Consolas', monospace;

/* Font Sizes - Desktop */
--text-xs: 0.75rem;     /* 12px */
--text-sm: 0.875rem;    /* 14px */
--text-base: 1rem;      /* 16px */
--text-lg: 1.125rem;    /* 18px */
--text-xl: 1.25rem;     /* 20px */
--text-2xl: 1.5rem;     /* 24px */
--text-3xl: 1.875rem;   /* 30px */
--text-4xl: 2.25rem;    /* 36px */
--text-5xl: 3rem;       /* 48px */

/* Line Heights */
--leading-none: 1;
--leading-tight: 1.25;
--leading-snug: 1.375;
--leading-normal: 1.5;
--leading-relaxed: 1.625;
--leading-loose: 2;

/* Font Weights */
--font-light: 300;
--font-normal: 400;
--font-medium: 500;
--font-semibold: 600;
--font-bold: 700;
```

### Spacing System

```css
/* Base unit: 8px */
--space-0: 0;
--space-1: 0.25rem;   /* 4px */
--space-2: 0.5rem;    /* 8px */
--space-3: 0.75rem;   /* 12px */
--space-4: 1rem;      /* 16px */
--space-5: 1.25rem;   /* 20px */
--space-6: 1.5rem;    /* 24px */
--space-8: 2rem;      /* 32px */
--space-10: 2.5rem;   /* 40px */
--space-12: 3rem;     /* 48px */
--space-16: 4rem;     /* 64px */
--space-20: 5rem;     /* 80px */
--space-24: 6rem;     /* 96px */
```

### Elevation & Shadows

```css
/* Shadow Levels */
--shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
--shadow-base: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
--shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
--shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
--shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
--shadow-2xl: 0 25px 50px -12px rgba(0, 0, 0, 0.25);

/* AI Glow Effects */
--glow-ai: 0 0 20px rgba(108, 92, 231, 0.3);
--glow-action: 0 0 15px rgba(0, 206, 201, 0.3);
```

### Border Radius

```css
--radius-none: 0;
--radius-sm: 0.125rem;    /* 2px */
--radius-base: 0.25rem;   /* 4px */
--radius-md: 0.375rem;    /* 6px */
--radius-lg: 0.5rem;      /* 8px */
--radius-xl: 0.75rem;     /* 12px */
--radius-2xl: 1rem;       /* 16px */
--radius-full: 9999px;    /* Pill shape */
```

### Animation & Transitions

```css
/* Timing Functions */
--ease-in: cubic-bezier(0.4, 0, 1, 1);
--ease-out: cubic-bezier(0, 0, 0.2, 1);
--ease-in-out: cubic-bezier(0.4, 0, 0.2, 1);
--ease-bounce: cubic-bezier(0.68, -0.55, 0.265, 1.55);

/* Durations */
--duration-75: 75ms;
--duration-100: 100ms;
--duration-150: 150ms;
--duration-200: 200ms;
--duration-300: 300ms;
--duration-500: 500ms;
--duration-700: 700ms;
--duration-1000: 1000ms;

/* Standard Transitions */
--transition-base: all 200ms ease-out;
--transition-fast: all 150ms ease-out;
--transition-slow: all 300ms ease-out;
```

## Component Library

### Buttons

#### Primary Button
```html
<button class="aura-btn aura-btn-primary">
  <span class="aura-btn-text">Get Started</span>
</button>
```

```css
.aura-btn {
  display: inline-flex;
  align-items: center;
  padding: var(--space-3) var(--space-6);
  border-radius: var(--radius-lg);
  font-weight: var(--font-medium);
  transition: var(--transition-base);
  cursor: pointer;
  border: none;
  font-size: var(--text-base);
}

.aura-btn-primary {
  background-color: var(--aura-primary-500);
  color: white;
}

.aura-btn-primary:hover {
  background-color: var(--aura-primary-600);
  transform: translateY(-1px);
  box-shadow: var(--shadow-md);
}
```

#### AI Action Button
```html
<button class="aura-btn aura-btn-ai">
  <svg class="aura-btn-icon"><!-- AI icon --></svg>
  <span class="aura-btn-text">Ask Aura</span>
</button>
```

```css
.aura-btn-ai {
  background: linear-gradient(135deg, var(--aura-intelligence-500), var(--aura-intelligence-600));
  color: white;
  box-shadow: var(--glow-ai);
}
```

### Cards

#### Basic Card
```html
<div class="aura-card">
  <div class="aura-card-header">
    <h3 class="aura-card-title">Card Title</h3>
  </div>
  <div class="aura-card-body">
    <p>Card content goes here</p>
  </div>
  <div class="aura-card-footer">
    <button class="aura-btn aura-btn-text">Action</button>
  </div>
</div>
```

```css
.aura-card {
  background: white;
  border-radius: var(--radius-xl);
  box-shadow: var(--shadow-base);
  overflow: hidden;
  transition: var(--transition-base);
}

.aura-card:hover {
  box-shadow: var(--shadow-md);
  transform: translateY(-2px);
}

.aura-card-header {
  padding: var(--space-4);
  border-bottom: 1px solid var(--aura-gray-200);
}

.aura-card-body {
  padding: var(--space-4);
}
```

### Forms

#### Input Field
```html
<div class="aura-form-group">
  <label class="aura-label" for="email">Email Address</label>
  <input type="email" id="email" class="aura-input" placeholder="you@example.com">
  <span class="aura-helper-text">We'll never share your email</span>
</div>
```

```css
.aura-input {
  width: 100%;
  padding: var(--space-3) var(--space-4);
  border: 2px solid var(--aura-gray-300);
  border-radius: var(--radius-lg);
  font-size: var(--text-base);
  transition: var(--transition-fast);
}

.aura-input:focus {
  outline: none;
  border-color: var(--aura-primary-500);
  box-shadow: 0 0 0 3px rgba(46, 58, 135, 0.1);
}
```

### Navigation

#### Tab Navigation
```html
<nav class="aura-tabs">
  <button class="aura-tab aura-tab-active">Dashboard</button>
  <button class="aura-tab">Tasks</button>
  <button class="aura-tab">Calendar</button>
  <button class="aura-tab">Settings</button>
</nav>
```

```css
.aura-tabs {
  display: flex;
  border-bottom: 2px solid var(--aura-gray-200);
}

.aura-tab {
  padding: var(--space-3) var(--space-4);
  background: none;
  border: none;
  font-weight: var(--font-medium);
  color: var(--aura-gray-600);
  position: relative;
  transition: var(--transition-fast);
}

.aura-tab-active {
  color: var(--aura-primary-500);
}

.aura-tab-active::after {
  content: '';
  position: absolute;
  bottom: -2px;
  left: 0;
  right: 0;
  height: 2px;
  background: var(--aura-primary-500);
}
```

### AI Components

#### AI Suggestion Card
```html
<div class="aura-ai-suggestion">
  <div class="aura-ai-icon">
    <svg><!-- AI icon --></svg>
  </div>
  <div class="aura-ai-content">
    <p class="aura-ai-text">I noticed you have back-to-back meetings. Would you like me to add 15-minute breaks?</p>
    <div class="aura-ai-actions">
      <button class="aura-btn aura-btn-ai-accept">Yes, add breaks</button>
      <button class="aura-btn aura-btn-text">No thanks</button>
    </div>
  </div>
</div>
```

```css
.aura-ai-suggestion {
  display: flex;
  gap: var(--space-4);
  padding: var(--space-4);
  background: linear-gradient(135deg, var(--aura-intelligence-100), var(--aura-intelligence-50));
  border-radius: var(--radius-xl);
  border: 1px solid var(--aura-intelligence-200);
}

.aura-ai-icon {
  width: 48px;
  height: 48px;
  background: var(--aura-intelligence-500);
  border-radius: var(--radius-full);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
}
```

#### Voice Input Visualizer
```html
<div class="aura-voice-input">
  <button class="aura-voice-button">
    <svg class="aura-voice-icon"><!-- Mic icon --></svg>
  </button>
  <div class="aura-voice-waves">
    <span class="aura-wave"></span>
    <span class="aura-wave"></span>
    <span class="aura-wave"></span>
    <span class="aura-wave"></span>
    <span class="aura-wave"></span>
  </div>
</div>
```

```css
.aura-voice-button {
  width: 64px;
  height: 64px;
  border-radius: var(--radius-full);
  background: var(--aura-action-500);
  border: none;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: var(--shadow-lg);
  transition: var(--transition-base);
}

.aura-voice-button:active {
  transform: scale(0.95);
}

.aura-wave {
  display: inline-block;
  width: 3px;
  height: 20px;
  background: var(--aura-action-500);
  margin: 0 2px;
  border-radius: var(--radius-full);
  animation: wave 1s ease-in-out infinite;
}

@keyframes wave {
  0%, 100% { transform: scaleY(1); }
  50% { transform: scaleY(2); }
}
```

### Loading States

#### Skeleton Loader
```html
<div class="aura-skeleton">
  <div class="aura-skeleton-line"></div>
  <div class="aura-skeleton-line aura-skeleton-short"></div>
</div>
```

```css
.aura-skeleton-line {
  height: 12px;
  background: linear-gradient(90deg, 
    var(--aura-gray-200) 25%, 
    var(--aura-gray-100) 50%, 
    var(--aura-gray-200) 75%);
  background-size: 200% 100%;
  animation: shimmer 1.5s infinite;
  border-radius: var(--radius-base);
  margin-bottom: var(--space-2);
}

@keyframes shimmer {
  0% { background-position: 200% 0; }
  100% { background-position: -200% 0; }
}
```

## Layout System

### Grid System
```css
.aura-container {
  width: 100%;
  max-width: 1200px;
  margin: 0 auto;
  padding: 0 var(--space-4);
}

.aura-grid {
  display: grid;
  gap: var(--space-4);
}

/* Responsive columns */
.aura-grid-cols-1 { grid-template-columns: repeat(1, 1fr); }
.aura-grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
.aura-grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
.aura-grid-cols-4 { grid-template-columns: repeat(4, 1fr); }

/* Mobile-first responsive */
@media (min-width: 768px) {
  .md\:aura-grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
  .md\:aura-grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
}

@media (min-width: 1024px) {
  .lg\:aura-grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
  .lg\:aura-grid-cols-4 { grid-template-columns: repeat(4, 1fr); }
}
```

### Flex Utilities
```css
.aura-flex { display: flex; }
.aura-inline-flex { display: inline-flex; }
.aura-flex-row { flex-direction: row; }
.aura-flex-col { flex-direction: column; }
.aura-items-center { align-items: center; }
.aura-justify-center { justify-content: center; }
.aura-justify-between { justify-content: space-between; }
.aura-gap-2 { gap: var(--space-2); }
.aura-gap-4 { gap: var(--space-4); }
```

## Motion Design

### Page Transitions
```css
/* Fade transition */
.aura-fade-enter {
  opacity: 0;
}

.aura-fade-enter-active {
  opacity: 1;
  transition: opacity 300ms ease-out;
}

/* Slide transition */
.aura-slide-enter {
  transform: translateX(100%);
}

.aura-slide-enter-active {
  transform: translateX(0);
  transition: transform 300ms ease-out;
}

/* Scale transition */
.aura-scale-enter {
  transform: scale(0.9);
  opacity: 0;
}

.aura-scale-enter-active {
  transform: scale(1);
  opacity: 1;
  transition: all 200ms ease-out;
}
```

### Micro-interactions
```css
/* Hover lift */
.aura-hover-lift {
  transition: transform 200ms ease-out, box-shadow 200ms ease-out;
}

.aura-hover-lift:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

/* Pulse animation */
.aura-pulse {
  animation: pulse 2s infinite;
}

@keyframes pulse {
  0% { opacity: 1; }
  50% { opacity: 0.5; }
  100% { opacity: 1; }
}

/* AI thinking animation */
.aura-ai-thinking {
  position: relative;
  overflow: hidden;
}

.aura-ai-thinking::after {
  content: '';
  position: absolute;
  top: 0;
  left: -100%;
  width: 100%;
  height: 100%;
  background: linear-gradient(90deg, 
    transparent, 
    rgba(108, 92, 231, 0.3), 
    transparent);
  animation: thinking 1.5s infinite;
}

@keyframes thinking {
  0% { left: -100%; }
  100% { left: 100%; }
}
```

## Accessibility Patterns

### Focus States
```css
/* Visible focus indicator */
.aura-focusable:focus {
  outline: 2px solid var(--aura-primary-500);
  outline-offset: 2px;
}

/* Focus visible only for keyboard navigation */
.aura-focusable:focus:not(:focus-visible) {
  outline: none;
}

.aura-focusable:focus-visible {
  outline: 2px solid var(--aura-primary-500);
  outline-offset: 2px;
}
```

### Screen Reader Utilities
```css
/* Visually hidden but accessible */
.aura-sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border-width: 0;
}

/* Show on focus */
.aura-sr-only-focusable:focus {
  position: static;
  width: auto;
  height: auto;
  padding: inherit;
  margin: inherit;
  overflow: visible;
  clip: auto;
  white-space: normal;
}
```

## Dark Mode Support

```css
/* Dark mode variables */
@media (prefers-color-scheme: dark) {
  :root {
    --aura-bg-primary: #1a1a1a;
    --aura-bg-secondary: #2d2d2d;
    --aura-text-primary: #ffffff;
    --aura-text-secondary: #b3b3b3;
    
    /* Adjust shadows for dark mode */
    --shadow-base: 0 1px 3px 0 rgba(0, 0, 0, 0.3);
    --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
  }
  
  .aura-card {
    background: var(--aura-bg-secondary);
    color: var(--aura-text-primary);
  }
}

/* Manual dark mode toggle */
.dark {
  --aura-bg-primary: #1a1a1a;
  --aura-bg-secondary: #2d2d2d;
  /* ... other dark mode overrides */
}
```

## Implementation Guidelines

### Component Usage
1. Always use semantic HTML elements
2. Include ARIA labels for complex interactions
3. Ensure all interactive elements are keyboard accessible
4. Test with screen readers
5. Maintain consistent spacing using the spacing system

### Performance Best Practices
1. Use CSS custom properties for theming
2. Implement lazy loading for images
3. Minimize animation on reduced motion preference
4. Use will-change sparingly for animations
5. Optimize SVG icons

### Responsive Design
1. Design mobile-first
2. Use relative units (rem, em) for scalability
3. Test on actual devices, not just browser DevTools
4. Ensure touch targets are at least 44x44px
5. Consider thumb reach on mobile devices

## Evolution Through Phases

### Phase 1: Foundation
- Basic color palette
- Simple components
- Standard interactions

### Phase 2: Intelligence
- AI color gradients
- Voice visualization components
- Animated feedback states

### Phase 3: Integration
- Service status indicators
- Complex card layouts
- Multi-step workflows

### Phase 4: Orchestration
- Advanced AI visualizations
- Predictive UI elements
- Contextual adaptations

This design system provides the foundation for building consistent, accessible, and beautiful interfaces across all Aura touchpoints, evolving from simple task management to sophisticated life orchestration.