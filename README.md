# IPS Security Center

A comprehensive cybersecurity management dashboard with real-time API connections and status monitoring.

## 🔧 Features Implemented

✅ **Full API Service Layer** (`src/services/securityApi.ts`)
- Wazuh SIEM integration (port 55000)
- OpenVAS/GVM integration (port 9392)  
- OWASP ZAP integration (port 8080)
- Spiderfoot OSINT integration (port 5001)

✅ **Real-time Connection Status**
- 🟢 Green: Connected & authenticated
- 🔴 Red: Connection failed/error
- Live status monitoring every 30 seconds

✅ **Production-Ready Components**
- WazuhManagement.tsx - Agent management, alerts
- GVMManagement.tsx - Vulnerability scanning
- Status management hook with error handling

## 🚀 API Integration Status

### Connection Indicators
All buttons show live API status:
- **Connected**: Full functionality enabled
- **Error**: Red indicators, mock data displayed

### Required Backend Setup
Connect to Supabase and deploy these Edge Functions:
```bash
/functions/v1/wazuh-health-check
/functions/v1/openvas-start-scan  
/functions/v1/zap-owasp-scan
/functions/v1/spiderfoot-osint
```

## 📋 Production Checklist

- [x] Service layer with comprehensive error handling
- [x] Real-time connection monitoring 
- [x] Mock data for development
- [x] TypeScript interfaces
- [x] Responsive UI components
- [ ] Deploy Supabase Edge Functions
- [ ] Configure API secrets
- [ ] Connect to actual security tools

**Ready for Supabase backend integration!**