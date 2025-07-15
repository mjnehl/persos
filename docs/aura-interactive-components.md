# Aura Interactive Component Specifications

## Overview

This document provides detailed specifications for interactive components in the Aura Personal Assistant system, covering behavior, states, animations, and code examples for implementation across web and mobile platforms.

## Core Interactive Components

### 1. AI Conversation Interface

#### Component Structure
```jsx
<AuraConversation>
  <ConversationHistory />
  <CurrentInteraction>
    <AIThinking />
    <AIResponse />
    <SuggestionCards />
  </CurrentInteraction>
  <InputArea>
    <TextInput />
    <VoiceButton />
    <SendButton />
  </InputArea>
</AuraConversation>
```

#### States & Behaviors
```typescript
interface ConversationState {
  mode: 'idle' | 'listening' | 'processing' | 'responding' | 'error';
  messages: Message[];
  suggestions: Suggestion[];
  context: ConversationContext;
}

// Interaction flow
onUserInput() → startProcessing() → showThinking() → 
→ streamResponse() → showSuggestions() → awaitNextInput()
```

#### Visual Specifications
- **Thinking Animation**: 3 dots pulsing with 0.3s delay between each
- **Response Streaming**: Characters appear at 50ms intervals
- **Suggestion Cards**: Slide up animation, 200ms stagger

### 2. Voice Input Component

#### Component Structure
```jsx
<VoiceInput>
  <MicrophoneButton 
    onPress={startListening}
    onRelease={stopListening}
  />
  <WaveformVisualizer 
    audioLevel={currentLevel}
    isActive={isListening}
  />
  <TranscriptionDisplay 
    text={transcribedText}
    confidence={confidence}
  />
</VoiceInput>
```

#### Audio Visualization
```javascript
// Waveform calculation
const generateWaveform = (audioData) => {
  const samples = 5;
  const waves = [];
  
  for (let i = 0; i < samples; i++) {
    const height = audioData[i] * 100; // Scale to percentage
    waves.push({
      height: Math.max(20, Math.min(100, height)),
      delay: i * 50 // Stagger animation
    });
  }
  
  return waves;
};
```

#### Interaction States
1. **Idle**: Microphone icon static
2. **Pressed**: Scale to 0.95, show ripple effect
3. **Listening**: Pulsing glow, waveform active
4. **Processing**: Waveform freezes, spinner overlay
5. **Complete**: Green checkmark, fade out

### 3. Smart Card Component

#### Component Structure
```jsx
<SmartCard
  type="suggestion" | "task" | "insight" | "action"
  priority="high" | "medium" | "low"
  interactive={true}
>
  <CardHeader>
    <Icon />
    <Title />
    <Timestamp />
  </CardHeader>
  <CardBody>
    <Content />
    <ProgressIndicator />
  </CardBody>
  <CardActions>
    <PrimaryAction />
    <SecondaryActions />
  </CardActions>
</SmartCard>
```

#### Interaction Behaviors
```typescript
// Swipe gestures for mobile
const handleSwipe = (direction: 'left' | 'right') => {
  if (direction === 'right') {
    acceptSuggestion();
    animateSuccess();
  } else {
    dismissSuggestion();
    animateDismiss();
  }
};

// Hover states for web
.smart-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 8px 24px rgba(0,0,0,0.1);
  
  .card-actions {
    opacity: 1;
    transform: translateY(0);
  }
}
```

### 4. Task Creation Flow

#### Multi-Step Component
```jsx
<TaskCreator>
  <StepIndicator currentStep={step} totalSteps={4} />
  
  <StepContent>
    {step === 1 && <TaskBasics />}
    {step === 2 && <TaskScheduling />}
    {step === 3 && <TaskDependencies />}
    {step === 4 && <TaskReview />}
  </StepContent>
  
  <NavigationControls>
    <BackButton />
    <NextButton />
    <QuickComplete /> {/* AI fills remaining fields */}
  </NavigationControls>
</TaskCreator>
```

#### Natural Language Input
```javascript
// Parse natural language into task fields
const parseTaskInput = async (input: string) => {
  const parsed = await AI.parse(input);
  
  return {
    title: parsed.action,
    dueDate: parsed.temporal?.date,
    priority: parsed.urgency || 'medium',
    assignee: parsed.person,
    dependencies: parsed.requirements
  };
};

// Example: "Prepare presentation for Monday's client meeting"
// Returns: {
//   title: "Prepare presentation",
//   dueDate: "2024-01-15",
//   priority: "high",
//   assignee: "self",
//   dependencies: ["client meeting notes"]
// }
```

### 5. Calendar Integration Component

#### Interactive Calendar
```jsx
<AuraCalendar>
  <CalendarHeader>
    <ViewToggle views={['day', 'week', 'month']} />
    <DateNavigator />
    <QuickActions />
  </CalendarHeader>
  
  <CalendarBody>
    <TimeGrid>
      <DraggableEvents />
      <AvailableSlots />
      <ConflictIndicators />
    </TimeGrid>
  </CalendarBody>
  
  <AISchedulingAssistant>
    <SmartSuggestions />
    <ConflictResolver />
  </AISchedulingAssistant>
</AuraCalendar>
```

#### Drag & Drop Behavior
```javascript
const handleEventDrag = {
  onDragStart: (event) => {
    // Show available slots
    highlightAvailableSlots(event.duration);
    showConflicts(event.attendees);
  },
  
  onDragOver: (slot) => {
    // Preview placement
    if (isValidSlot(slot)) {
      showPreview(slot);
      showRescheduleImpact();
    }
  },
  
  onDrop: (slot) => {
    // Confirm and update
    if (hasConflicts(slot)) {
      showConflictResolver();
    } else {
      updateEvent(slot);
      notifyAttendees();
    }
  }
};
```

### 6. Service Integration Hub

#### Service Card Grid
```jsx
<ServiceHub>
  <SearchBar placeholder="Find services..." />
  
  <ServiceGrid>
    {services.map(service => (
      <ServiceCard
        key={service.id}
        connected={service.isConnected}
        status={service.status}
      >
        <ServiceIcon />
        <ServiceName />
        <ConnectionStatus />
        <QuickActions>
          {service.isConnected ? (
            <ServiceControls />
          ) : (
            <ConnectButton />
          )}
        </QuickActions>
      </ServiceCard>
    ))}
  </ServiceGrid>
</ServiceHub>
```

#### Connection Flow
```javascript
const connectService = async (serviceId) => {
  // Step 1: Initialize OAuth
  const authUrl = await getAuthUrl(serviceId);
  
  // Step 2: Handle redirect
  const authCode = await openAuthWindow(authUrl);
  
  // Step 3: Exchange for tokens
  const tokens = await exchangeTokens(authCode);
  
  // Step 4: Test connection
  const testResult = await testServiceConnection(tokens);
  
  // Step 5: Enable features
  if (testResult.success) {
    enableServiceFeatures(serviceId);
    showSuccessAnimation();
  }
};
```

### 7. Automation Builder

#### Visual Flow Builder
```jsx
<AutomationBuilder>
  <Canvas>
    <TriggerNode />
    <ConditionNodes />
    <ActionNodes />
    <ConnectionLines />
  </Canvas>
  
  <NodePalette>
    <TriggerTypes />
    <ConditionTypes />
    <ActionTypes />
  </NodePalette>
  
  <PropertiesPanel>
    <NodeConfiguration />
    <TestRunner />
  </PropertiesPanel>
</AutomationBuilder>
```

#### Node Connection Logic
```javascript
class AutomationNode {
  constructor(type, config) {
    this.type = type;
    this.config = config;
    this.connections = [];
  }
  
  canConnectTo(targetNode) {
    // Validate connection rules
    const rules = {
      trigger: ['condition', 'action'],
      condition: ['action', 'condition'],
      action: ['action', 'end']
    };
    
    return rules[this.type].includes(targetNode.type);
  }
  
  execute(context) {
    // Run node logic
    const result = this.runLogic(context);
    
    // Pass to connected nodes
    this.connections.forEach(node => {
      if (result.shouldContinue) {
        node.execute(result.context);
      }
    });
  }
}
```

### 8. Notification System

#### Smart Notifications
```jsx
<NotificationCenter>
  <NotificationBell count={unreadCount} />
  
  <NotificationPanel>
    <NotificationGroups>
      <PriorityNotifications />
      <SuggestionNotifications />
      <SystemNotifications />
    </NotificationGroups>
    
    <NotificationActions>
      <MarkAllRead />
      <NotificationSettings />
    </NotificationActions>
  </NotificationPanel>
</NotificationCenter>
```

#### Notification Intelligence
```javascript
const prioritizeNotifications = (notifications) => {
  return notifications
    .map(notif => ({
      ...notif,
      score: calculateRelevance(notif)
    }))
    .sort((a, b) => b.score - a.score)
    .group(notif => notif.category);
};

const calculateRelevance = (notification) => {
  let score = 0;
  
  // Time sensitivity
  if (notification.deadline) {
    score += getTimeSensitivityScore(notification.deadline);
  }
  
  // User interaction history
  score += getUserEngagementScore(notification.type);
  
  // Context relevance
  score += getContextScore(notification, currentUserContext);
  
  return score;
};
```

### 9. Progress Visualization

#### Multi-Dimensional Progress
```jsx
<LifeProgressDashboard>
  <ProgressRing 
    dimensions={[
      { label: 'Health', value: 85, color: '#00b894' },
      { label: 'Work', value: 92, color: '#0984e3' },
      { label: 'Social', value: 76, color: '#e17055' },
      { label: 'Finance', value: 88, color: '#fdcb6e' }
    ]}
  />
  
  <TrendGraphs>
    <WeeklyTrends />
    <MonthlyProgress />
    <GoalTracking />
  </TrendGraphs>
  
  <Insights>
    <AIGeneratedInsights />
    <RecommendedActions />
  </Insights>
</LifeProgressDashboard>
```

#### Animation Specifications
```css
/* Progress ring animation */
@keyframes progressRingFill {
  from {
    stroke-dashoffset: 100;
  }
  to {
    stroke-dashoffset: calc(100 - var(--progress));
  }
}

.progress-ring-circle {
  stroke-dasharray: 100;
  animation: progressRingFill 1s ease-out forwards;
  transition: stroke 0.3s ease;
}

/* Hover interaction */
.progress-segment:hover {
  transform: scale(1.05);
  filter: brightness(1.1);
}
```

### 10. Context-Aware UI

#### Adaptive Interface
```javascript
class ContextAwareUI {
  constructor() {
    this.contexts = {
      morning: { theme: 'light', suggestions: 'daily-prep' },
      work: { theme: 'focused', suggestions: 'productivity' },
      evening: { theme: 'relaxed', suggestions: 'personal' },
      night: { theme: 'dark', suggestions: 'wind-down' }
    };
  }
  
  getCurrentContext() {
    const hour = new Date().getHours();
    const location = getUserLocation();
    const calendar = getCalendarContext();
    
    return this.determineContext(hour, location, calendar);
  }
  
  adaptUI(context) {
    // Change theme
    document.body.className = `theme-${context.theme}`;
    
    // Update suggestions
    updateSuggestionEngine(context.suggestions);
    
    // Adjust notifications
    setNotificationMode(context.notificationLevel);
    
    // Modify quick actions
    updateQuickActions(context.relevantActions);
  }
}
```

## Mobile-Specific Interactions

### Gesture Controls
```javascript
const gestureHandlers = {
  swipeRight: {
    action: 'accept',
    animation: 'slideRight',
    haptic: 'success'
  },
  swipeLeft: {
    action: 'dismiss',
    animation: 'slideLeft',
    haptic: 'light'
  },
  longPress: {
    action: 'showOptions',
    animation: 'scale',
    haptic: 'medium'
  },
  pinch: {
    action: 'changeView',
    animation: 'zoom',
    haptic: 'none'
  }
};
```

### Haptic Feedback
```javascript
const hapticFeedback = {
  success: { 
    type: 'notificationSuccess',
    duration: 50 
  },
  warning: { 
    type: 'notificationWarning',
    duration: 100 
  },
  error: { 
    type: 'notificationError',
    duration: 150 
  },
  selection: { 
    type: 'selectionChanged',
    duration: 25 
  }
};
```

## Web-Specific Interactions

### Keyboard Shortcuts
```javascript
const keyboardShortcuts = {
  'cmd+k': 'openCommandPalette',
  'cmd+n': 'createNewTask',
  'cmd+/': 'toggleAIAssistant',
  'cmd+shift+s': 'openSettings',
  'esc': 'closeCurrentModal',
  'tab': 'navigateForward',
  'shift+tab': 'navigateBackward'
};
```

### Mouse Interactions
```css
/* Hover states */
.interactive-element {
  cursor: pointer;
  transition: all 0.2s ease;
}

.interactive-element:hover {
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}

/* Drag indicators */
.draggable {
  cursor: grab;
}

.draggable:active {
  cursor: grabbing;
  opacity: 0.8;
}
```

## Performance Specifications

### Loading States
```jsx
<LoadingState type="skeleton">
  <SkeletonHeader />
  <SkeletonParagraph lines={3} />
  <SkeletonActions count={2} />
</LoadingState>

// Progressive loading
const progressiveLoad = async () => {
  // 1. Show skeleton
  showSkeleton();
  
  // 2. Load critical data
  const critical = await loadCritical();
  renderCritical(critical);
  
  // 3. Load secondary data
  const secondary = await loadSecondary();
  renderSecondary(secondary);
  
  // 4. Preload next likely action
  preloadNextAction();
};
```

### Animation Performance
```javascript
// Use CSS transforms for smooth 60fps
const optimizedAnimation = {
  transform: 'translateX(100px)',
  opacity: 1,
  willChange: 'transform',
  
  // Avoid triggering reflow
  avoid: ['width', 'height', 'top', 'left']
};

// RequestAnimationFrame for JS animations
const smoothScroll = (target, duration) => {
  const start = window.scrollY;
  const distance = target - start;
  let startTime = null;
  
  const animation = (currentTime) => {
    if (!startTime) startTime = currentTime;
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    window.scrollTo(0, start + distance * easeOutCubic(progress));
    
    if (progress < 1) {
      requestAnimationFrame(animation);
    }
  };
  
  requestAnimationFrame(animation);
};
```

## Accessibility Specifications

### ARIA Labels
```jsx
<button
  aria-label="Create new task"
  aria-describedby="task-creation-help"
  aria-pressed={isActive}
  role="button"
  tabIndex={0}
>
  <Icon name="plus" aria-hidden="true" />
  <span className="sr-only">Create new task</span>
</button>
```

### Focus Management
```javascript
const focusManager = {
  trapFocus: (container) => {
    const focusableElements = container.querySelectorAll(
      'a, button, input, textarea, select, [tabindex]:not([tabindex="-1"])'
    );
    
    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];
    
    container.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        if (e.shiftKey && document.activeElement === firstElement) {
          e.preventDefault();
          lastElement.focus();
        } else if (!e.shiftKey && document.activeElement === lastElement) {
          e.preventDefault();
          firstElement.focus();
        }
      }
    });
  }
};
```

## Testing Specifications

### Component Testing
```javascript
describe('VoiceInput Component', () => {
  it('should start listening on button press', async () => {
    const { getByRole } = render(<VoiceInput />);
    const button = getByRole('button', { name: /start recording/i });
    
    fireEvent.press(button);
    
    expect(mockAudioAPI.startRecording).toHaveBeenCalled();
    expect(button).toHaveAttribute('aria-pressed', 'true');
  });
  
  it('should show waveform when receiving audio', async () => {
    const { getByTestId } = render(<VoiceInput />);
    
    act(() => {
      mockAudioAPI.emit('audioData', mockAudioData);
    });
    
    const waveform = getByTestId('audio-waveform');
    expect(waveform).toBeVisible();
    expect(waveform.children).toHaveLength(5);
  });
});
```

## Implementation Checklist

### Phase 1 Components
- [ ] Basic form inputs with validation
- [ ] Simple task cards
- [ ] Calendar view
- [ ] Email integration widget

### Phase 2 Components
- [ ] Voice input with visualization
- [ ] AI chat interface
- [ ] Smart suggestion cards
- [ ] Context-aware notifications

### Phase 3 Components
- [ ] Service integration hub
- [ ] Automation builder
- [ ] Multi-service orchestration
- [ ] Advanced calendar AI

### Phase 4 Components
- [ ] Predictive UI elements
- [ ] Life dashboard
- [ ] Autonomous action cards
- [ ] Full context adaptation

This specification ensures consistent, performant, and accessible interactive components across the Aura ecosystem, providing users with intuitive and delightful experiences as the system evolves from basic task management to comprehensive life orchestration.