# Aura Zero-Knowledge API Specifications

## Overview

This document provides comprehensive API specifications for the Aura personal AI assistant system built on zero-knowledge architecture. All data is encrypted client-side before transmission, ensuring that Aura servers never have access to unencrypted user data. APIs follow RESTful principles with encrypted payloads.

## Base URLs

- **Production**: `https://api.aura.example.com`
- **Staging**: `https://api-staging.aura.example.com`
- **Local Development**: `http://localhost:8000`

## Zero-Knowledge Authentication

Authentication uses Secure Remote Password (SRP-6a) protocol, ensuring passwords never leave the client device.

### Zero-Knowledge Authentication Flow

#### Step 1: Initiate Authentication
```http
POST /auth/v1/srp/init
Content-Type: application/json

{
  "email": "user@example.com"
}

Response:
{
  "salt": "base64-encoded-salt",
  "server_public_key": "base64-encoded-B",
  "session_id": "auth-session-123"
}
```

#### Step 2: Complete Authentication
```http
POST /auth/v1/srp/verify
Content-Type: application/json

{
  "session_id": "auth-session-123",
  "client_public_key": "base64-encoded-A",
  "proof": "base64-encoded-M1"
}

Response:
{
  "server_proof": "base64-encoded-M2",
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "key_derivation_params": {
    "algorithm": "argon2id",
    "salt": "user-specific-salt",
    "iterations": 3,
    "memory": 65536
  },
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Using Authentication

Include the access token in the Authorization header:
```http
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### Key Management API

#### Rotate Encryption Keys
```http
POST /api/v1/keys/rotate
Authorization: Bearer {token}
Content-Type: application/json

{
  "current_key_proof": "base64-proof-of-current-key",
  "new_key_wrapped": "base64-new-key-wrapped-with-current",
  "re_encrypted_data_keys": {
    "data_key": "base64-reencrypted-data-key",
    "search_key": "base64-reencrypted-search-key"
  }
}

Response 200:
{
  "rotation_id": "rot_123",
  "status": "completed",
  "keys_rotated": 2,
  "data_re_encrypted": true,
  "completed_at": "2024-01-15T10:00:00Z"
}
```

#### Add Recovery Key
```http
POST /api/v1/keys/recovery
Authorization: Bearer {token}
Content-Type: application/json

{
  "recovery_shares": [
    {
      "share_id": "share_1",
      "encrypted_share": "base64-encrypted-share-1",
      "guardian_email_hash": "sha256-hash-of-guardian-email"
    },
    {
      "share_id": "share_2", 
      "encrypted_share": "base64-encrypted-share-2",
      "guardian_email_hash": "sha256-hash-of-guardian-email"
    }
  ],
  "threshold": 2,
  "total_shares": 3
}

Response 201:
{
  "recovery_id": "rec_456",
  "shares_stored": 3,
  "threshold": 2,
  "created_at": "2024-01-15T10:00:00Z"
}
```

## API Endpoints

### User Management

#### Get User Profile
```http
GET /api/v1/users/profile
Authorization: Bearer {token}

Response 200:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "John Doe",
  "subscription_tier": "pro",
  "created_at": "2024-01-15T09:00:00Z",
  "preferences": {
    "timezone": "America/New_York",
    "language": "en",
    "theme": "dark"
  }
}
```

#### Update User Profile
```http
PATCH /api/v1/users/profile
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "John Smith",
  "preferences": {
    "timezone": "Europe/London"
  }
}

Response 200:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "name": "John Smith",
  "updated_at": "2024-01-15T10:00:00Z"
}
```

### Encrypted Context Management

#### Store Encrypted Context
```http
POST /api/v1/context/store
Authorization: Bearer {token}
Content-Type: application/json

{
  "encrypted_type": "base64-encrypted-type",
  "encrypted_category": "base64-encrypted-category",
  "encrypted_data": "base64-encrypted-json-data",
  "search_tokens": [
    "hmac-token-1",
    "hmac-token-2"
  ],
  "nonce": "base64-nonce",
  "checksum": "sha256-checksum"
}

Response 201:
{
  "id": "ctx_123456",
  "stored": true,
  "created_at": "2024-01-15T10:00:00Z"
}
```

#### Client-Side Encryption Example
```javascript
// Client encrypts before sending
const context = {
  type: "preference",
  category: "meetings",
  data: {
    preferred_duration: 30,
    buffer_time: 15
  }
};

const encrypted = await encryptContext(context, userKey);
const searchTokens = await generateSearchTokens(context, searchKey);

// Send encrypted data to server
const response = await api.post('/context/store', {
  encrypted_type: encrypted.type,
  encrypted_data: encrypted.data,
  search_tokens: searchTokens,
  nonce: encrypted.nonce,
  checksum: encrypted.checksum
});
```

#### Search Encrypted Context
```http
POST /api/v1/context/search
Authorization: Bearer {token}
Content-Type: application/json

{
  "search_tokens": [
    "hmac-search-token-1",
    "hmac-search-token-2"
  ],
  "limit": 50
}

Response 200:
{
  "encrypted_contexts": [
    {
      "id": "ctx_123456",
      "encrypted_type": "base64-encrypted-type",
      "encrypted_data": "base64-encrypted-data",
      "nonce": "base64-nonce",
      "created_at": "2024-01-15T08:00:00Z",
      "last_accessed": "2024-01-15T09:00:00Z"
    }
  ],
  "total": 1,
  "limit": 50
}
```

Note: The client must decrypt the returned data using their key.
```

### Privacy-Preserving AI Interaction

#### Process Encrypted Request
```http
POST /api/v1/ai/process
Authorization: Bearer {token}
Content-Type: application/json

{
  "encrypted_message": "base64-encrypted-user-message",
  "encrypted_context": "base64-encrypted-context",
  "processing_mode": "secure_enclave",
  "nonce": "base64-nonce",
  "key_proof": "base64-key-ownership-proof"
}

Response 200:
{
  "intent": {
    "type": "schedule_meeting",
    "confidence": 0.95,
    "entities": {
      "person": "Sarah",
      "date": "2024-01-23",
      "time_preference": "afternoon"
    }
  },
  "plan": {
    "steps": [
      {
        "id": "step_1",
        "action": "find_contact",
        "parameters": {
          "name": "Sarah"
        },
        "status": "pending"
      },
      {
        "id": "step_2",
        "action": "check_availability",
        "parameters": {
          "date": "2024-01-23",
          "time_range": "13:00-17:00"
        },
        "depends_on": ["step_1"],
        "status": "pending"
      },
      {
        "id": "step_3",
        "action": "create_event",
        "parameters": {
          "title": "Meeting with Sarah",
          "date": "2024-01-23",
          "duration": 60
        },
        "depends_on": ["step_2"],
        "requires_approval": true,
        "status": "pending"
      }
    ]
  },
  "reasoning": "I understood you want to schedule a meeting with Sarah next Tuesday (January 23rd) in the afternoon. I'll need to find Sarah's contact information, check both of your calendars for availability, and create the meeting invite.",
  "requires_approval": true,
  "workflow_id": "wf_abc123"
}
```

#### Get AI Suggestions
```http
GET /api/v1/ai/suggestions?context=daily_planning
Authorization: Bearer {token}

Response 200:
{
  "suggestions": [
    {
      "id": "sug_123",
      "type": "task_reminder",
      "priority": "high",
      "message": "You have a report due tomorrow for the quarterly review",
      "action": {
        "type": "block_time",
        "parameters": {
          "duration": 120,
          "task": "Complete quarterly report"
        }
      }
    },
    {
      "id": "sug_124",
      "type": "wellness",
      "priority": "medium",
      "message": "You've been in meetings for 3 hours. Consider taking a break.",
      "action": {
        "type": "schedule_break",
        "parameters": {
          "duration": 15
        }
      }
    }
  ],
  "generated_at": "2024-01-15T14:00:00Z"
}
```

### Task Management

#### Create Task
```http
POST /api/v1/tasks
Authorization: Bearer {token}
Content-Type: application/json

{
  "type": "calendar_event",
  "title": "Team Standup",
  "description": "Daily team synchronization",
  "parameters": {
    "start_time": "2024-01-16T09:00:00Z",
    "end_time": "2024-01-16T09:30:00Z",
    "attendees": ["team@example.com"],
    "recurrence": "RRULE:FREQ=DAILY;BYDAY=MO,TU,WE,TH,FR"
  },
  "integration": "google_calendar"
}

Response 201:
{
  "id": "task_789",
  "type": "calendar_event",
  "status": "pending",
  "workflow_id": "wf_def456",
  "created_at": "2024-01-15T10:00:00Z",
  "estimated_completion": "2024-01-15T10:00:30Z"
}
```

#### Get Task Status
```http
GET /api/v1/tasks/task_789
Authorization: Bearer {token}

Response 200:
{
  "id": "task_789",
  "type": "calendar_event",
  "status": "completed",
  "title": "Team Standup",
  "workflow_id": "wf_def456",
  "created_at": "2024-01-15T10:00:00Z",
  "completed_at": "2024-01-15T10:00:15Z",
  "result": {
    "success": true,
    "calendar_event_id": "google_event_123",
    "message": "Recurring event created successfully"
  },
  "steps": [
    {
      "name": "validate_parameters",
      "status": "completed",
      "duration_ms": 50
    },
    {
      "name": "check_conflicts",
      "status": "completed",
      "duration_ms": 200
    },
    {
      "name": "create_event",
      "status": "completed",
      "duration_ms": 1500
    }
  ]
}
```

#### List Tasks
```http
GET /api/v1/tasks?status=pending,in_progress&limit=20
Authorization: Bearer {token}

Response 200:
{
  "tasks": [
    {
      "id": "task_790",
      "type": "email_draft",
      "title": "Draft response to client proposal",
      "status": "in_progress",
      "created_at": "2024-01-15T11:00:00Z",
      "progress": 0.75
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

### Integration Management

#### List Available Integrations
```http
GET /api/v1/integrations/available
Authorization: Bearer {token}

Response 200:
{
  "integrations": [
    {
      "id": "google_calendar",
      "name": "Google Calendar",
      "category": "calendar",
      "description": "Sync and manage Google Calendar events",
      "features": [
        "event_creation",
        "availability_check",
        "attendee_management"
      ],
      "required_scopes": [
        "https://www.googleapis.com/auth/calendar"
      ],
      "icon_url": "https://api.aura.example.com/icons/google_calendar.png"
    },
    {
      "id": "slack",
      "name": "Slack",
      "category": "communication",
      "description": "Send messages and manage Slack workspaces",
      "features": [
        "send_message",
        "create_reminder",
        "status_update"
      ],
      "required_scopes": [
        "chat:write",
        "users:write"
      ]
    }
  ]
}
```

#### Connect Integration
```http
POST /api/v1/integrations/connect
Authorization: Bearer {token}
Content-Type: application/json

{
  "integration_id": "google_calendar",
  "auth_code": "4/0AX4XfWj...",
  "redirect_uri": "https://app.aura.example.com/integrations/callback"
}

Response 201:
{
  "id": "conn_123",
  "integration_id": "google_calendar",
  "status": "connected",
  "connected_at": "2024-01-15T10:00:00Z",
  "permissions": [
    "calendar.events.read",
    "calendar.events.write"
  ],
  "account_info": {
    "email": "user@gmail.com",
    "name": "John Doe"
  }
}
```

#### List Connected Integrations
```http
GET /api/v1/integrations/connected
Authorization: Bearer {token}

Response 200:
{
  "connections": [
    {
      "id": "conn_123",
      "integration_id": "google_calendar",
      "status": "active",
      "connected_at": "2024-01-15T10:00:00Z",
      "last_sync": "2024-01-15T14:00:00Z",
      "account_info": {
        "email": "user@gmail.com"
      }
    }
  ]
}
```

### Calendar Operations

#### Get Calendar Events
```http
GET /api/v1/calendar/events?start=2024-01-15&end=2024-01-22
Authorization: Bearer {token}

Response 200:
{
  "events": [
    {
      "id": "evt_123",
      "title": "Team Meeting",
      "start": "2024-01-16T14:00:00Z",
      "end": "2024-01-16T15:00:00Z",
      "location": "Conference Room A",
      "attendees": [
        {
          "email": "colleague@example.com",
          "name": "Jane Smith",
          "status": "accepted"
        }
      ],
      "source": "google_calendar",
      "is_recurring": false
    }
  ],
  "date_range": {
    "start": "2024-01-15T00:00:00Z",
    "end": "2024-01-22T23:59:59Z"
  }
}
```

#### Find Available Time Slots
```http
POST /api/v1/calendar/availability
Authorization: Bearer {token}
Content-Type: application/json

{
  "duration_minutes": 60,
  "date_range": {
    "start": "2024-01-16",
    "end": "2024-01-19"
  },
  "time_preferences": {
    "earliest": "09:00",
    "latest": "17:00",
    "preferred_times": ["morning"]
  },
  "attendees": ["colleague@example.com"],
  "buffer_minutes": 15
}

Response 200:
{
  "available_slots": [
    {
      "start": "2024-01-16T09:00:00Z",
      "end": "2024-01-16T10:00:00Z",
      "confidence": 1.0,
      "conflicts": []
    },
    {
      "start": "2024-01-17T14:00:00Z",
      "end": "2024-01-17T15:00:00Z",
      "confidence": 0.8,
      "conflicts": [
        {
          "type": "soft",
          "reason": "Close to lunch time"
        }
      ]
    }
  ]
}
```

### Email Operations

#### Get Email Summary
```http
GET /api/v1/email/summary?hours=24
Authorization: Bearer {token}

Response 200:
{
  "summary": {
    "total_emails": 47,
    "unread": 12,
    "high_priority": 3,
    "requires_response": 5,
    "categories": {
      "work": 30,
      "personal": 10,
      "newsletters": 5,
      "spam": 2
    }
  },
  "important_emails": [
    {
      "id": "email_123",
      "from": "boss@company.com",
      "subject": "Urgent: Project deadline update",
      "preview": "We need to discuss the new timeline for...",
      "received_at": "2024-01-15T08:30:00Z",
      "priority": "high",
      "suggested_action": "respond_immediately"
    }
  ],
  "generated_at": "2024-01-15T10:00:00Z"
}
```

#### Draft Email Response
```http
POST /api/v1/email/draft
Authorization: Bearer {token}
Content-Type: application/json

{
  "in_reply_to": "email_123",
  "tone": "professional",
  "key_points": [
    "Acknowledge the deadline change",
    "Confirm team capacity",
    "Suggest meeting to discuss"
  ],
  "length": "medium"
}

Response 200:
{
  "draft": {
    "subject": "Re: Urgent: Project deadline update",
    "body": "Dear [Boss Name],\n\nThank you for informing me about the updated project timeline. I've reviewed the new deadline with our team, and I can confirm that we have the capacity to meet it with some adjustments to our current sprint.\n\nTo ensure we're aligned on priorities and resource allocation, I'd like to suggest a brief meeting this week. Would Thursday afternoon work for you?\n\nBest regards,\n[Your name]",
    "suggested_send_time": "2024-01-15T10:30:00Z"
  },
  "alternatives": [
    {
      "tone": "more_formal",
      "preview": "I acknowledge receipt of your message regarding..."
    }
  ]
}
```

### Smart Home Integration

#### Get Device Status
```http
GET /api/v1/home/devices
Authorization: Bearer {token}

Response 200:
{
  "devices": [
    {
      "id": "device_001",
      "name": "Living Room Lights",
      "type": "light",
      "status": "on",
      "attributes": {
        "brightness": 75,
        "color_temp": 3000
      },
      "room": "living_room"
    },
    {
      "id": "device_002",
      "name": "Thermostat",
      "type": "climate",
      "status": "heating",
      "attributes": {
        "current_temp": 68,
        "target_temp": 72,
        "mode": "heat"
      }
    }
  ]
}
```

#### Execute Home Automation
```http
POST /api/v1/home/automate
Authorization: Bearer {token}
Content-Type: application/json

{
  "scene": "arriving_home",
  "parameters": {
    "eta_minutes": 15,
    "preferences": {
      "temperature": 72,
      "lighting": "warm"
    }
  }
}

Response 200:
{
  "executed_actions": [
    {
      "device": "Thermostat",
      "action": "set_temperature",
      "target": 72,
      "status": "success"
    },
    {
      "device": "Living Room Lights",
      "action": "turn_on",
      "brightness": 50,
      "status": "scheduled",
      "execute_at": "2024-01-15T18:00:00Z"
    }
  ],
  "scene_status": "active"
}
```

### Notification Management

#### Get Notification Preferences
```http
GET /api/v1/notifications/preferences
Authorization: Bearer {token}

Response 200:
{
  "channels": {
    "push": {
      "enabled": true,
      "quiet_hours": {
        "start": "22:00",
        "end": "08:00"
      }
    },
    "email": {
      "enabled": true,
      "digest_frequency": "daily"
    },
    "sms": {
      "enabled": false
    }
  },
  "categories": {
    "task_reminders": {
      "channels": ["push"],
      "priority": "high"
    },
    "suggestions": {
      "channels": ["push"],
      "priority": "low"
    },
    "system_alerts": {
      "channels": ["push", "email"],
      "priority": "critical"
    }
  }
}
```

#### Update Notification Preferences
```http
PUT /api/v1/notifications/preferences
Authorization: Bearer {token}
Content-Type: application/json

{
  "channels": {
    "push": {
      "quiet_hours": {
        "start": "23:00",
        "end": "07:00"
      }
    }
  },
  "categories": {
    "suggestions": {
      "channels": ["email"],
      "priority": "medium"
    }
  }
}

Response 200:
{
  "updated": true,
  "updated_at": "2024-01-15T10:00:00Z"
}
```

### Analytics & Insights

#### Get Personal Analytics
```http
GET /api/v1/analytics/personal?period=week
Authorization: Bearer {token}

Response 200:
{
  "period": {
    "start": "2024-01-08",
    "end": "2024-01-15"
  },
  "productivity": {
    "focus_time_hours": 28.5,
    "meeting_hours": 12.0,
    "task_completion_rate": 0.85,
    "average_task_time_minutes": 45
  },
  "wellness": {
    "break_compliance": 0.70,
    "overtime_hours": 3.5,
    "stress_indicators": "moderate"
  },
  "communication": {
    "emails_processed": 156,
    "average_response_time_hours": 2.5,
    "meetings_attended": 18,
    "meetings_declined": 3
  },
  "insights": [
    {
      "type": "productivity_tip",
      "message": "Your most productive hours are 9-11 AM. Consider scheduling important tasks during this time.",
      "confidence": 0.85
    },
    {
      "type": "wellness_alert",
      "message": "You've been skipping breaks on busy days. Short breaks can improve overall productivity.",
      "confidence": 0.90
    }
  ]
}
```

### Search

#### Universal Search
```http
GET /api/v1/search?q=meeting%20with%20sarah&types=events,emails,tasks
Authorization: Bearer {token}

Response 200:
{
  "results": [
    {
      "type": "event",
      "id": "evt_456",
      "title": "Meeting with Sarah - Project Review",
      "date": "2024-01-10T14:00:00Z",
      "relevance_score": 0.95,
      "highlights": {
        "title": "<em>Meeting with Sarah</em> - Project Review"
      }
    },
    {
      "type": "email",
      "id": "email_789",
      "subject": "Re: Meeting with Sarah",
      "from": "sarah@example.com",
      "date": "2024-01-09T16:30:00Z",
      "relevance_score": 0.88,
      "preview": "Confirming our <em>meeting</em> for tomorrow at 2 PM..."
    }
  ],
  "facets": {
    "type": {
      "event": 3,
      "email": 8,
      "task": 2
    },
    "date_range": {
      "this_week": 5,
      "last_week": 6,
      "older": 2
    }
  },
  "total_results": 13,
  "query_time_ms": 125
}
```

## WebSocket API

### Real-time Updates

Connect to WebSocket endpoint:
```
wss://api.aura.example.com/ws
```

#### Authentication
```json
{
  "type": "auth",
  "token": "Bearer eyJhbGciOiJSUzI1NiIs..."
}
```

#### Subscribe to Events
```json
{
  "type": "subscribe",
  "channels": ["tasks", "notifications", "calendar"]
}
```

#### Receiving Updates
```json
{
  "type": "task_update",
  "data": {
    "task_id": "task_123",
    "status": "completed",
    "result": {
      "success": true,
      "message": "Email sent successfully"
    }
  },
  "timestamp": "2024-01-15T10:00:00Z"
}
```

## Support Access Control API

### Request Support Access
```http
POST /api/v1/support/access/request
Authorization: Bearer {token}
Content-Type: application/json

{
  "ticket_id": "SUPPORT-123",
  "issue_description": "Cannot sync calendar events",
  "requested_data_categories": ["calendar_metadata", "sync_logs"],
  "requested_permissions": ["view_sync_status", "run_diagnostics"]
}

Response 201:
{
  "request_id": "req_abc123",
  "status": "pending_user_approval",
  "agent_id": "agent_456",
  "agent_name": "Support Tech Jane",
  "expires_at": "2024-01-16T10:00:00Z"
}
```

### Grant Support Access
```http
POST /api/v1/support/access/grant
Authorization: Bearer {token}
Content-Type: application/json

{
  "request_id": "req_abc123",
  "approved": true,
  "granted_permissions": ["view_sync_status", "run_diagnostics"],
  "granted_categories": ["calendar_metadata"],
  "duration_hours": 24,
  "restrictions": {
    "read_only": true,
    "exclude_fields": ["event_details", "attendee_emails"]
  }
}

Response 200:
{
  "grant_id": "grant_789",
  "status": "active",
  "valid_until": "2024-01-16T10:00:00Z",
  "access_key_encrypted": "base64-encrypted-for-agent",
  "audit_log_url": "/api/v1/audit/grants/grant_789"
}
```

### Revoke Support Access
```http
DELETE /api/v1/support/access/grants/{grant_id}
Authorization: Bearer {token}

Response 200:
{
  "grant_id": "grant_789",
  "status": "revoked",
  "revoked_at": "2024-01-15T12:00:00Z",
  "data_deleted": true
}
```

### Monitor Support Access
```http
GET /api/v1/support/access/activity?grant_id=grant_789
Authorization: Bearer {token}

Response 200:
{
  "grant_id": "grant_789",
  "agent_id": "agent_456",
  "status": "active",
  "access_log": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "action": "view_sync_status",
      "data_accessed": "calendar_sync_metadata",
      "ip_address": "10.0.0.50",
      "result": "success"
    },
    {
      "timestamp": "2024-01-15T10:35:00Z",
      "action": "run_diagnostics",
      "diagnostic_type": "connectivity_check",
      "result": "completed"
    }
  ],
  "expires_at": "2024-01-16T10:00:00Z"
}
```

## Audit Trail API

### Get Audit Log
```http
GET /api/v1/audit/log?start_date=2024-01-01&end_date=2024-01-15&types=support_access,data_access
Authorization: Bearer {token}

Response 200:
{
  "entries": [
    {
      "entry_id": "audit_123",
      "timestamp": "2024-01-15T10:00:00Z",
      "event_type": "support_access_request",
      "actor_id": "agent_456",
      "actor_type": "support_agent",
      "action": "request_access",
      "result": "pending",
      "metadata": {
        "ticket_id": "SUPPORT-123",
        "requested_permissions": ["view_sync_status"]
      },
      "entry_hash": "sha256:abc123...",
      "previous_hash": "sha256:def456..."
    }
  ],
  "pagination": {
    "total": 42,
    "page": 1,
    "per_page": 20
  },
  "integrity": {
    "valid": true,
    "merkle_root": "sha256:789abc..."
  }
}
```

### Verify Audit Integrity
```http
POST /api/v1/audit/verify
Authorization: Bearer {token}
Content-Type: application/json

{
  "start_date": "2024-01-01",
  "end_date": "2024-01-15",
  "entry_hashes": [
    "sha256:abc123...",
    "sha256:def456..."
  ]
}

Response 200:
{
  "valid": true,
  "entries_verified": 42,
  "merkle_root": "sha256:789abc...",
  "issues": [],
  "verification_timestamp": "2024-01-15T15:00:00Z"
}
```

## Error Handling

### Error Response Format
```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested task was not found",
    "details": {
      "task_id": "task_999",
      "suggestion": "Task may have been deleted or you lack permission to access it"
    }
  },
  "request_id": "req_abc123",
  "timestamp": "2024-01-15T10:00:00Z"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `UNAUTHORIZED` | 401 | Invalid or missing authentication token |
| `FORBIDDEN` | 403 | Insufficient permissions for requested operation |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource does not exist |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTEGRATION_ERROR` | 502 | External service error |
| `INTERNAL_ERROR` | 500 | Internal server error |

## Rate Limiting

API rate limits are enforced per user:

| Endpoint Category | Limit | Window |
|-------------------|-------|---------|
| AI Processing | 10 requests | 1 minute |
| General API | 100 requests | 1 minute |
| Search | 30 requests | 1 minute |
| Bulk Operations | 10 requests | 10 minutes |

Rate limit headers in responses:
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1673784000
```

## Versioning

The API uses URL versioning. Current version is `v1`. When breaking changes are introduced, a new version will be created while maintaining backward compatibility for a deprecation period.

Example:
- Current: `/api/v1/tasks`
- Future: `/api/v2/tasks`

## SDK Examples

### JavaScript/TypeScript
```typescript
import { AuraClient } from '@aura/sdk';

const client = new AuraClient({
  apiKey: process.env.AURA_API_KEY,
  baseUrl: 'https://api.aura.example.com'
});

// Process natural language
const response = await client.ai.process({
  message: "Schedule lunch with Mike tomorrow at noon"
});

// Create a task
const task = await client.tasks.create({
  type: 'calendar_event',
  title: 'Lunch with Mike',
  parameters: {
    start_time: '2024-01-16T12:00:00Z',
    duration_minutes: 60
  }
});
```

### Python
```python
from aura_sdk import AuraClient

client = AuraClient(
    api_key=os.environ['AURA_API_KEY'],
    base_url='https://api.aura.example.com'
)

# Get email summary
summary = client.email.get_summary(hours=24)

# Find available meeting times
slots = client.calendar.find_availability(
    duration_minutes=30,
    date_range={
        'start': '2024-01-16',
        'end': '2024-01-18'
    }
)
```

## Webhooks

Configure webhooks to receive real-time updates:

### Webhook Configuration
```http
POST /api/v1/webhooks
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": "https://myapp.example.com/webhooks/aura",
  "events": ["task.completed", "calendar.event.created"],
  "secret": "webhook-secret-key"
}

Response 201:
{
  "id": "webhook_123",
  "url": "https://myapp.example.com/webhooks/aura",
  "events": ["task.completed", "calendar.event.created"],
  "status": "active",
  "created_at": "2024-01-15T10:00:00Z"
}
```

### Webhook Payload
```json
{
  "id": "evt_123",
  "type": "task.completed",
  "data": {
    "task_id": "task_456",
    "status": "completed",
    "result": {
      "success": true
    }
  },
  "timestamp": "2024-01-15T10:00:00Z",
  "signature": "sha256=..."
}
```

## Testing

### Sandbox Environment

Use the sandbox environment for testing:
- Base URL: `https://sandbox-api.aura.example.com`
- Test credentials available in developer dashboard
- Data is reset daily

### Test Data

Pre-populated test accounts are available:
- `test-user-basic@aura.example.com`: Basic tier features
- `test-user-pro@aura.example.com`: Pro tier features
- `test-user-enterprise@aura.example.com`: All features enabled

## Support

- Documentation: https://docs.aura.example.com
- API Status: https://status.aura.example.com
- Developer Forum: https://forum.aura.example.com
- Email: api-support@aura.example.com