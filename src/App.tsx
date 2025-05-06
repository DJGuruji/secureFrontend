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
  TextField
} from '@mui/material';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import FileUpload from './components/FileUpload';
import ScanHistory from './components/ScanHistory';
import CloseIcon from '@mui/icons-material/Close';
import VisibilityIcon from '@mui/icons-material/Visibility';
import ScanResults from './components/ScanResults';
import { format } from 'date-fns';

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
              <Typography variant="h6" gutterBottom>
                Scan Summary
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="error">
                      {daptResults.severity_count.ERROR || 0}
                    </Typography>
                    <Typography variant="body2">High Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="warning.main">
                      {daptResults.severity_count.WARNING || 0}
                    </Typography>
                    <Typography variant="body2">Medium Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="info.main">
                      {daptResults.severity_count.INFO || 0}
                    </Typography>
                    <Typography variant="body2">Low Risk</Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                Findings
              </Typography>
              {daptResults.vulnerabilities.map((vuln, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2 }}>
                  <Typography variant="subtitle1" color={vuln.extra.severity === 'ERROR' ? 'error' : vuln.extra.severity === 'WARNING' ? 'warning.main' : 'info.main'}>
                    {vuln.extra.message} ({vuln.extra.severity})
                  </Typography>
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
              <Typography variant="h6" gutterBottom>
                Scan Summary
              </Typography>
              <Grid container spacing={2} sx={{ mb: 3 }}>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="error">
                      {scanResults.severity_count.ERROR || 0}
                    </Typography>
                    <Typography variant="body2">High Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="warning.main">
                      {scanResults.severity_count.WARNING || 0}
                    </Typography>
                    <Typography variant="body2">Medium Risk</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6} sm={3}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h4" color="info.main">
                      {scanResults.severity_count.INFO || 0}
                    </Typography>
                    <Typography variant="body2">Low Risk</Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                Findings
              </Typography>
              {scanResults.vulnerabilities.map((vuln, index) => (
                <Paper key={index} sx={{ p: 2, mb: 2 }}>
                  <Typography variant="subtitle1" color={vuln.extra.severity === 'ERROR' ? 'error' : vuln.extra.severity === 'WARNING' ? 'warning.main' : 'info.main'}>
                    {vuln.extra.message} ({vuln.extra.severity})
                  </Typography>
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