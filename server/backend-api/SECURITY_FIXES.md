# File Upload Security Fixes

This document outlines the comprehensive security improvements implemented for file upload endpoints in the Smart Attendance backend API.

## Security Vulnerabilities Addressed

### 1. Path Traversal Prevention
- **Issue**: Filenames were not sanitized, allowing potential path traversal attacks
- **Fix**: Implemented comprehensive filename sanitization in `FileSecurityValidator`
- **Features**:
  - Removes path components (`../`, `..\\`)
  - Detects and blocks dangerous patterns
  - Sanitizes Windows reserved characters and names
  - Generates safe fallback names using content hashes

### 2. Magic Number Validation
- **Issue**: Only MIME type headers were checked, vulnerable to spoofing
- **Fix**: Added file signature validation using magic numbers
- **Features**:
  - Validates JPEG (`\xff\xd8\xff`), PNG (`\x89PNG`), and WebP (`RIFF...WEBP`) signatures
  - Fallback to python-magic library for comprehensive detection
  - Rejects files with mismatched content and headers

### 3. Metadata Stripping
- **Issue**: EXIF and other metadata was preserved, potential privacy/security risk
- **Fix**: Automatic metadata removal from uploaded images
- **Features**:
  - Strips EXIF data from JPEG files
  - Removes PNG metadata chunks
  - Preserves image quality while removing sensitive information
  - Logs metadata removal for audit purposes

### 4. Rate Limiting
- **Issue**: No upload frequency restrictions, vulnerable to DoS attacks
- **Fix**: Implemented sliding window rate limiting with Redis backend
- **Features**:
  - Student face uploads: 20 per hour per user
  - Teacher avatar uploads: 5 per hour per user
  - Redis-based with in-memory fallback
  - Proper HTTP 429 responses with retry headers

### 5. Enhanced File Validation
- **Issue**: Weak content verification and size checks
- **Fix**: Comprehensive validation pipeline
- **Features**:
  - File size limits (5MB configurable)
  - Image dimension validation (4096x4096 max)
  - Minimum dimension checks (10x10 pixels)
  - Content integrity verification with SHA-256 hashes

## Implementation Details

### New Security Components

#### 1. FileSecurityValidator (`app/utils/file_security.py`)
```python
# Comprehensive file validation and security processing
validator = FileSecurityValidator()
result = await validator.validate_upload_file(file, max_size=5MB, strip_metadata=True)
```

**Features**:
- Magic number validation
- Filename sanitization
- Metadata stripping
- Image property validation
- Content integrity hashing

#### 2. RateLimiter (`app/utils/rate_limiter.py`)
```python
# Rate limiting enforcement
await enforce_upload_rate_limit(user_id, "face_image_upload", request)
```

**Features**:
- Redis-based sliding window algorithm
- Configurable limits per operation type
- Graceful fallback to in-memory storage
- Proper HTTP headers for client guidance

#### 3. SecurityConfig (`app/core/security_config.py`)
```python
# Centralized security configuration
from app.core.security_config import security_config, log_security_event
```

**Features**:
- Environment-based configuration
- Security feature toggles
- Audit logging utilities
- Validation helpers

### Updated Endpoints

#### Student Face Image Upload (`/students/me/face-image`)
**Security Enhancements**:
- Rate limiting (20 uploads/hour)
- Magic number validation
- Metadata stripping
- Secure Cloudinary naming
- Audit trail with file hashes
- Comprehensive error handling

#### Teacher Avatar Upload (`/settings/upload-avatar`)
**Security Enhancements**:
- Rate limiting (5 uploads/hour)
- Magic number validation
- Metadata stripping
- Fixed Cloudinary folder name (`avatars` vs `avtars`)
- Secure public ID generation
- Enhanced error handling

### Security Headers and Middleware

The existing security middleware (`SecurityHeadersMiddleware`) provides:
- X-XSS-Protection
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Content Security Policy
- HSTS (production)

### Audit Logging

All security events are logged with:
- User identification
- File hashes for integrity
- Validation results
- Upload success/failure
- Rate limiting violations

## Configuration

### Environment Variables

```bash
# File upload security
MAX_FILE_SIZE=5242880  # 5MB in bytes
STRIP_METADATA=true
VALIDATE_MAGIC_NUMBERS=true

# Rate limiting
REDIS_URL=redis://localhost:6379
RATE_LIMIT_ENABLED=true

# Security features
SECURITY_AUDIT_LOGGING_ENABLED=true
SECURITY_HEADERS_ENABLED=true
```

### Rate Limit Configuration

```python
RATE_LIMIT_CONFIGS = {
    'file_upload': {
        'max_requests': 10,
        'window_seconds': 3600,
    },
    'avatar_upload': {
        'max_requests': 5,
        'window_seconds': 3600,
    },
    'face_image_upload': {
        'max_requests': 20,
        'window_seconds': 3600,
    }
}
```

## Testing

### Security Test Coverage

The test suite (`tests/test_image_upload_validation.py`) includes:

1. **File Size Validation**
   - Oversized file rejection (413 status)
   - Valid size acceptance

2. **File Type Validation**
   - Magic number verification
   - MIME type spoofing detection
   - Invalid file type rejection

3. **Filename Security**
   - Path traversal prevention
   - Malicious filename sanitization

4. **Image Validation**
   - Dimension limits
   - Empty file rejection
   - WebP format support

5. **Rate Limiting**
   - Multiple upload simulation
   - Proper HTTP headers

### Running Security Tests

```bash
# Run all security tests
pytest tests/test_image_upload_validation.py -v

# Run specific security test
pytest tests/test_image_upload_validation.py::test_malicious_filename -v

# Run with coverage
pytest tests/test_image_upload_validation.py --cov=app.utils.file_security
```

## Security Best Practices Implemented

1. **Defense in Depth**: Multiple validation layers
2. **Fail Secure**: Reject by default, allow explicitly
3. **Audit Trail**: Comprehensive logging of security events
4. **Rate Limiting**: Prevent abuse and DoS attacks
5. **Input Sanitization**: Clean all user-provided data
6. **Content Validation**: Verify file contents match headers
7. **Metadata Removal**: Strip potentially sensitive information
8. **Secure Storage**: Use content hashes in storage identifiers

## Monitoring and Alerts

### Security Event Logging

All security events are logged with structured data:

```python
log_security_event(
    event_type="file_upload_validation_failed",
    user_id=user_id,
    details={
        "filename": original_filename,
        "reason": "magic_number_mismatch",
        "mime_type_header": file.content_type,
        "detected_type": detected_mime
    },
    level="WARNING"
)
```

### Recommended Monitoring

1. **Rate Limit Violations**: Monitor 429 responses
2. **Validation Failures**: Track rejected uploads by reason
3. **File Size Trends**: Monitor upload sizes for anomalies
4. **Magic Number Mismatches**: Detect spoofing attempts
5. **Metadata Stripping**: Track privacy protection effectiveness

## Performance Impact

### Optimizations Implemented

1. **Streaming Validation**: Process files without loading entirely into memory
2. **Efficient Magic Number Checks**: Only read first few bytes
3. **Redis Connection Pooling**: Reuse connections for rate limiting
4. **Cloudinary Optimization**: Auto-quality and format optimization
5. **Lazy Loading**: Import heavy libraries only when needed

### Expected Performance Impact

- **File Validation**: ~50-100ms additional processing time
- **Metadata Stripping**: ~100-200ms for JPEG files
- **Rate Limiting**: ~5-10ms Redis lookup
- **Overall Impact**: ~200-300ms additional latency per upload

## Deployment Considerations

### Dependencies

New dependencies added to `requirements.txt`:
```
python-magic>=0.4.27  # File type detection
Pillow>=10.0.0       # Image processing (already present)
```

### System Requirements

- **Redis**: Required for production rate limiting
- **libmagic**: System library for file type detection
- **Memory**: Additional ~50MB for image processing

### Production Deployment

1. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install libmagic1
   
   # CentOS/RHEL
   sudo yum install file-libs
   ```

2. **Configure Redis**:
   ```bash
   # Set Redis URL in environment
   export REDIS_URL=redis://your-redis-server:6379
   ```

3. **Enable security features**:
   ```bash
   export STRIP_METADATA=true
   export RATE_LIMIT_ENABLED=true
   export SECURITY_AUDIT_LOGGING_ENABLED=true
   ```

## Future Enhancements

### Planned Improvements

1. **Virus Scanning**: Integration with ClamAV or similar
2. **Advanced Rate Limiting**: IP-based and user-based combined limits
3. **File Quarantine**: Temporary storage for suspicious files
4. **Machine Learning**: Anomaly detection for upload patterns
5. **Blockchain Integrity**: Immutable audit trail for critical uploads

### Security Monitoring Dashboard

Consider implementing:
- Real-time upload monitoring
- Security event visualization
- Rate limiting metrics
- File validation statistics
- User behavior analytics

## Compliance and Standards

This implementation addresses:

- **OWASP Top 10**: File upload vulnerabilities
- **GDPR**: Privacy protection through metadata removal
- **SOC 2**: Security controls and audit logging
- **ISO 27001**: Information security management

## Support and Maintenance

### Log Locations

- **Application logs**: `/var/log/smart-attendance/app.log`
- **Security audit logs**: `/var/log/smart-attendance/security.log`
- **Rate limiting logs**: Redis logs + application logs

### Troubleshooting

Common issues and solutions:

1. **Magic number validation fails**: Check file format and python-magic installation
2. **Rate limiting not working**: Verify Redis connection and configuration
3. **Metadata stripping errors**: Check Pillow installation and image format support
4. **Performance issues**: Monitor memory usage and consider scaling Redis

For additional support, refer to the security team or create an issue in the project repository.