import React, { useState } from 'react';
import { 
  Container, 
  Box, 
  Typography, 
  Paper, 
  CircularProgress,
  Alert,
  Grid,
  Tabs,
  Tab,
  useTheme,
  useMediaQuery,
  Button,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
  TextField,
  LinearProgress
} from '@mui/material';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import FileUpload from './components/FileUpload';
import ScanHistory from './components/ScanHistory';
import CloseIcon from '@mui/icons-material/Close';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ScanResults from './components/ScanResults';
import { format } from 'date-fns';
import WarningIcon from '@mui/icons-material/Warning';
import ErrorIcon from '@mui/icons-material/Error';
import InfoIcon from '@mui/icons-material/Info';
import TimerIcon from '@mui/icons-material/Timer';
import CalendarTodayIcon from '@mui/icons-material/CalendarToday';
import SecurityIcon from '@mui/icons-material/Security';

interface Vulnerability {
  check_id: string;
  path: string;
  start: any;
  end: any;
  extra: any;
  severity: string;
  message: string;
}

interface DAPTResult {
  findings: Array<{
    risk: string;
    name: string;
    description: string;
    solution: string;
    reference: string;
    cweid: string;
    wascid: string;
    evidence: string;
    confidence: string;
  }>;
  severity_count: {
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  total_vulnerabilities: number;
  security_score: number;
  scan_duration: number;
  tool_version: string;
  environment: string;
  target_url: string;
  html_report: string;
  scan_id: string;
}

const API_UPLOAD_URL = 'http://localhost:8000/api/v1/scan/upload';
const API_SCAN_URL = 'http://localhost:8000/api/v1/scan/scan';
const API_DAST_URL = 'http://localhost:8000/api/v1/scan/dast';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ p: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

function App() {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));
  const [scanResults, setScanResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [tabValue, setTabValue] = useState(0);
  const [uploadedFile, setUploadedFile] = useState<File | null>(null);
  const [scanStarted, setScanStarted] = useState(false);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [targetUrl, setTargetUrl] = useState('');
  const [daptLoading, setDaptLoading] = useState(false);
  const [daptResults, setDaptResults] = useState<any>(null);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  const onDrop = (acceptedFiles: File[]) => {
    if (acceptedFiles.length === 0) return;
    setUploadedFile(acceptedFiles[0]);
    setScanResults(null);
    setScanStarted(false);
    setError(null);
  };

  const startScan = async () => {
    if (!uploadedFile) return;
    setLoading(true);
    setError(null);
    setScanStarted(true);
    const formData = new FormData();
    formData.append('file', uploadedFile);
    try {
      const response = await fetch(API_UPLOAD_URL, {
        method: 'POST',
        credentials: 'include',
        body: formData,
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to scan file');
      }
      const data = await response.json();
      setScanResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const startDaptScan = async () => {
    if (!targetUrl) return;
    setDaptLoading(true);
    setError(null);
    try {
      const response = await fetch(API_DAST_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ target_url: targetUrl }),
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to run DAST scan');
      }
      
      const data = await response.json();
      setDaptResults(data);
      setDialogOpen(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setDaptLoading(false);
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/zip': ['.zip'],
      'text/x-python': ['.py'],
      'application/javascript': ['.js'],
      'application/typescript': ['.ts'],
      'text/x-java': ['.java'],
      'text/x-c++src': ['.cpp'],
      'text/x-csrc': ['.c'],
      'text/x-csharp': ['.cs'],
      'application/x-httpd-php': ['.php'],
      'application/x-ruby': ['.rb'],
      'text/x-go': ['.go'],
      'text/x-rust': ['.rs'],
      'text/plain': ['.txt'],
      'application/x-msdownload': ['.exe'],
      'application/x-sh': ['.sh'],
    },
    multiple: false,
  });

  // Helper to classify vulnerabilities
const classifyVulns = (vulns: Vulnerability[]) => {
  const result = { VULNERABLE: [], MODERATE: [], INFO: [] } as Record<string, Vulnerability[]>;
  vulns.forEach(vuln => {
    const rawSeverity = vuln.severity;
    const sev = (rawSeverity || 'info').toLowerCase();
    console.log('Classifying vulnerability - raw severity:', rawSeverity, '| processed:', sev);
    if (sev === 'error') {
      result.VULNERABLE.push(vuln);
    } else if (sev === 'warning') {
      result.MODERATE.push(vuln);
    } else {
      result.INFO.push(vuln); // fallback
    }
  });
  return result;
};


  // Handler for viewing scan details from history
  const handleViewScan = async (scanId: string) => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch(`${API_SCAN_URL}/${scanId}`, {
        credentials: 'include',
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || 'Failed to fetch scan details');
      }
      const data = await response.json();
      setScanResults(data);
      setDialogOpen(true);
    } catch (err) {
      setError('Failed to load scan details. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleCloseDialog = () => {
    setDialogOpen(false);
    setScanResults(null);
    setDaptResults(null);
  };

  // Update the calculateScore function to use stored score
  const calculateScore = (results: any) => {
    if (!results) return 0;
    // Use the stored security score if available, otherwise calculate it
    if (results.security_score !== undefined) {
      return Math.round(results.security_score * 10) / 10;
    }
    
    // Fallback calculation if security_score is not available
    const severityCount = results.severity_count || {};
    const total = (severityCount.ERROR || 0) + (severityCount.WARNING || 0) + (severityCount.INFO || 0);
    if (total === 0) return 10;
    
    const weight = {
      ERROR: 1,
      WARNING: 0.5,
      INFO: 0.1
    };
    
    const weightedScore = 
      (severityCount.ERROR || 0) * weight.ERROR +
      (severityCount.WARNING || 0) * weight.WARNING +
      (severityCount.INFO || 0) * weight.INFO;
    
    const score = Math.round((10 - (weightedScore / total) * 10) * 10) / 10;
    return Math.max(0, Math.min(10, score));
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ my: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center" color="primary">
          Code Vulnerability Scanner
        </Typography>
        <Typography variant="h6" component="h2" gutterBottom align="center" color="text.secondary">
          Upload your code to analyze security vulnerabilities
        </Typography>
        <Paper elevation={3} sx={{ width: '100%', mb: 2, position: 'relative', zIndex: 1 }}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs
              value={tabValue}
              onChange={handleTabChange}
              indicatorColor="primary"
              textColor="primary"
              centered
              sx={{ '& .MuiTab-root': { minWidth: 100, fontWeight: 'bold' } }}
            >
              <Tab label="Upload" />
              <Tab label="DAPT" />
              <Tab label="History" />
            </Tabs>
          </Box>
          <TabPanel value={tabValue} index={0}>
            <FileUpload
              getRootProps={getRootProps}
              getInputProps={getInputProps}
              isDragActive={isDragActive}
              loading={loading}
            />
            {uploadedFile && (
              <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                <Button 
                  variant="contained" 
                  color="primary" 
                  size="large" 
                  onClick={startScan} 
                  disabled={loading}
                >
                  {loading ? 'Running SAST...' : 'SAST'}
                </Button>
              </Box>
            )}
            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}
            {scanResults && !loading && (
              <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                <Button
                  variant="contained"
                  color="primary"
                  onClick={() => setDialogOpen(true)}
                  startIcon={<VisibilityIcon />}
                >
                  View Results
                </Button>
              </Box>
            )}
          </TabPanel>
          <TabPanel value={tabValue} index={1}>
            <Box sx={{ p: 3 }}>
              <Typography variant="h6" gutterBottom>
                Dynamic Application Penetration Testing
              </Typography>
              <Box sx={{ mb: 3 }}>
                <TextField
                  fullWidth
                  label="Target URL"
                  variant="outlined"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://example.com"
                  sx={{ mb: 2 }}
                />
                <Button
                  variant="contained"
                  color="primary"
                  onClick={startDaptScan}
                  disabled={daptLoading || !targetUrl}
                  fullWidth
                >
                  {daptLoading ? 'Running DAPT...' : 'Start DAPT Scan'}
                </Button>
              </Box>
              {error && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {error}
                </Alert>
              )}
              {daptResults && !daptLoading && (
                <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                  <Button
                    variant="contained"
                    color="primary"
                    onClick={() => setDialogOpen(true)}
                    startIcon={<VisibilityIcon />}
                  >
                    View DAPT Results
                  </Button>
                </Box>
              )}
            </Box>
          </TabPanel>
          <TabPanel value={tabValue} index={2}>
            <ScanHistory onViewScan={handleViewScan} />
          </TabPanel>
        </Paper>
      </Box>
      
      <Dialog
        open={dialogOpen}
        onClose={handleCloseDialog}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>
          {daptResults ? 'DAST Scan Results' : 'Scan Results'}
          <IconButton
            aria-label="close"
            onClick={handleCloseDialog}
            sx={{ position: 'absolute', right: 8, top: 8 }}
          >
            <CloseIcon />
          </IconButton>
        </DialogTitle>
        <DialogContent>
          {daptResults ? (
            <Box sx={{ mt: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
                <Box sx={{ position: 'relative', display: 'inline-flex', mr: 3 }}>
                  <CircularProgress
                    variant="determinate"
                    value={calculateScore(daptResults) * 10}
                    size={120}
                    thickness={4}
                    sx={{
                      color: (theme) => {
                        const score = calculateScore(daptResults);
                        if (score >= 8) return theme.palette.success.main;
                        if (score >= 6) return theme.palette.warning.main;
                        return theme.palette.error.main;
                      }
                    }}
                  />
                  <Box
                    sx={{
                      top: 0,
                      left: 0,
                      bottom: 0,
                      right: 0,
                      position: 'absolute',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Typography variant="h4" component="div" color="text.secondary">
                      {calculateScore(daptResults)}/10
                    </Typography>
                  </Box>
                </Box>
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Security Score
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Based on vulnerability severity and count
                  </Typography>
                </Box>
              </Box>

              <Grid container spacing={2} sx={{ mb: 4 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                      <CalendarTodayIcon sx={{ mr: 1 }} />
                      Scan Date
                    </Typography>
                    <Typography variant="body2">
                      {new Date(daptResults.scan_metadata?.scan_date || Date.now()).toLocaleString()}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                      <TimerIcon sx={{ mr: 1 }} />
                      Processing Duration
                    </Typography>
                    <Typography variant="body2">
                      {daptResults.scan_metadata?.scan_duration || 0} seconds
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                <SecurityIcon sx={{ mr: 1 }} />
                Vulnerability Summary
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <ErrorIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                    <Typography variant="h4" color="error">
                      {daptResults.severity_count.ERROR || 0}
                    </Typography>
                    <Typography variant="body2">High Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <WarningIcon color="warning" sx={{ fontSize: 40, mb: 1 }} />
                    <Typography variant="h4" color="warning.main">
                      {daptResults.severity_count.WARNING || 0}
                    </Typography>
                    <Typography variant="body2">Medium Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <InfoIcon color="info" sx={{ fontSize: 40, mb: 1 }} />
                    <Typography variant="h4" color="info.main">
                      {daptResults.severity_count.INFO || 0}
                    </Typography>
                    <Typography variant="body2">Low Risk</Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                Detailed Findings
              </Typography>
              {daptResults.vulnerabilities.map((vuln, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    {vuln.extra.severity === 'ERROR' ? (
                      <ErrorIcon color="error" sx={{ mr: 1 }} />
                    ) : vuln.extra.severity === 'WARNING' ? (
                      <WarningIcon color="warning" sx={{ mr: 1 }} />
                    ) : (
                      <InfoIcon color="info" sx={{ mr: 1 }} />
                    )}
                    <Typography variant="subtitle1" color={vuln.extra.severity === 'ERROR' ? 'error' : vuln.extra.severity === 'WARNING' ? 'warning.main' : 'info.main'}>
                      {vuln.extra.message}
                    </Typography>
                  </Box>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    {vuln.extra.description}
                  </Typography>
                  <Typography variant="subtitle2" sx={{ mt: 1 }}>
                    Solution:
                  </Typography>
                  <Typography variant="body2">
                    {vuln.extra.solution}
                  </Typography>
                  {vuln.extra.reference && (
                    <>
                      <Typography variant="subtitle2" sx={{ mt: 1 }}>
                        Reference:
                      </Typography>
                      <Typography variant="body2">
                        {vuln.extra.reference}
                      </Typography>
                    </>
                  )}
                </Paper>
              ))}

              {daptResults.scan_metadata?.report_html && (
                <>
                  <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                    Full Report
                  </Typography>
                  <Paper sx={{ p: 2 }}>
                    <iframe
                      srcDoc={daptResults.scan_metadata.report_html}
                      style={{ width: '100%', height: '500px', border: 'none' }}
                      title="OWASP ZAP Report"
                    />
                  </Paper>
                </>
              )}
            </Box>
          ) : scanResults ? (
            <Box sx={{ mt: 2 }}>
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
                <Box sx={{ position: 'relative', display: 'inline-flex', mr: 3 }}>
                  <CircularProgress
                    variant="determinate"
                    value={calculateScore(scanResults) * 10}
                    size={120}
                    thickness={4}
                    sx={{
                      color: (theme) => {
                        const score = calculateScore(scanResults);
                        if (score >= 8) return theme.palette.success.main;
                        if (score >= 6) return theme.palette.warning.main;
                        return theme.palette.error.main;
                      }
                    }}
                  />
                  <Box
                    sx={{
                      top: 0,
                      left: 0,
                      bottom: 0,
                      right: 0,
                      position: 'absolute',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                    }}
                  >
                    <Typography variant="h4" component="div" color="text.secondary">
                      {calculateScore(scanResults)}/10
                    </Typography>
                  </Box>
                </Box>
                <Box>
                  <Typography variant="h6" gutterBottom>
                    Security Score
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Based on vulnerability severity and count
                  </Typography>
                </Box>
              </Box>

              <Grid container spacing={2} sx={{ mb: 4 }}>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                      <CalendarTodayIcon sx={{ mr: 1 }} />
                      Scan Date
                    </Typography>
                    <Typography variant="body2">
                      {new Date(scanResults.scan_metadata?.scan_date || Date.now()).toLocaleString()}
                    </Typography>
                  </Paper>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Paper sx={{ p: 2 }}>
                    <Typography variant="subtitle1" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                      <TimerIcon sx={{ mr: 1 }} />
                      Processing Duration
                    </Typography>
                    <Typography variant="body2">
                      {scanResults.scan_metadata?.scan_duration || 0} seconds
                    </Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center' }}>
                <SecurityIcon sx={{ mr: 1 }} />
                Vulnerability Summary
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <ErrorIcon color="error" sx={{ fontSize: 40, mb: 1 }} />
                    <Typography variant="h4" color="error">
                      {scanResults.severity_count.ERROR || 0}
                    </Typography>
                    <Typography variant="body2">High Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <WarningIcon color="warning" sx={{ fontSize: 40, mb: 1 }} />
                    <Typography variant="h4" color="warning.main">
                      {scanResults.severity_count.WARNING || 0}
                    </Typography>
                    <Typography variant="body2">Medium Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <InfoIcon color="info" sx={{ fontSize: 40, mb: 1 }} />
                    <Typography variant="h4" color="info.main">
                      {scanResults.severity_count.INFO || 0}
                    </Typography>
                    <Typography variant="body2">Low Risk</Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                Detailed Findings
              </Typography>
              {scanResults.vulnerabilities.map((vuln, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                    {vuln.extra.severity === 'ERROR' ? (
                      <ErrorIcon color="error" sx={{ mr: 1 }} />
                    ) : vuln.extra.severity === 'WARNING' ? (
                      <WarningIcon color="warning" sx={{ mr: 1 }} />
                    ) : (
                      <InfoIcon color="info" sx={{ mr: 1 }} />
                    )}
                    <Typography variant="subtitle1" color={vuln.extra.severity === 'ERROR' ? 'error' : vuln.extra.severity === 'WARNING' ? 'warning.main' : 'info.main'}>
                      {vuln.extra.message}
                    </Typography>
                  </Box>
                  <Typography variant="body2" sx={{ mt: 1 }}>
                    {vuln.path}:{vuln.start.line}-{vuln.end.line}
                  </Typography>
                  {vuln.extra.description && (
                    <Typography variant="body2" sx={{ mt: 1 }}>
                      {vuln.extra.description}
                    </Typography>
                  )}
                  {vuln.extra.solution && (
                    <>
                      <Typography variant="subtitle2" sx={{ mt: 1 }}>
                        Solution:
                      </Typography>
                      <Typography variant="body2">
                        {vuln.extra.solution}
                      </Typography>
                    </>
                  )}
                </Paper>
              ))}
            </Box>
          ) : null}
        </DialogContent>
      </Dialog>
    </Container>
  );
}

export default App; 