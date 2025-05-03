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
  Chip
} from '@mui/material';
import { useDropzone } from 'react-dropzone';
import axios from 'axios';
import FileUpload from './components/FileUpload';
import ScanHistory from './components/ScanHistory';

interface Vulnerability {
  check_id: string;
  path: string;
  start: any;
  end: any;
  extra: any;
  severity: string;
  message: string;
}

const API_UPLOAD_URL = 'http://localhost:8000/api/v1/scan/upload';
const API_SCAN_URL = 'http://localhost:8000/api/v1/scan/scan';

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
        body: formData,
      });
      if (!response.ok) {
        throw new Error('Failed to scan file');
      }
      const data = await response.json();
      setScanResults(data);
      setTabValue(1); // Switch to Results tab
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
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
      const response = await fetch(`${API_SCAN_URL}/${scanId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch scan details');
      }
      const data = await response.json();
      setScanResults(data);
      setTabValue(0); // Switch to Upload tab (where results are now shown)
    } catch (err) {
      setError('Failed to load scan details. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container maxWidth="lg">
      <Box sx={{ my: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom align="center">
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
            {uploadedFile && !scanStarted && (
              <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
                <Button variant="contained" color="primary" size="large" onClick={startScan} disabled={loading}>
                  SAST
                </Button>
              </Box>
            )}
            {error && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}
            {loading && (
              <Box sx={{ display: 'flex', justifyContent: 'center', p: 3 }}>
                <CircularProgress />
              </Box>
            )}
            {scanResults && !loading && (
              <Box sx={{ mt: 4 }}>
                <Typography variant="h6" gutterBottom>
                  Scan Results
                </Typography>
                {(() => {
                  const classified = classifyVulns(scanResults.vulnerabilities || []);
                  return <>
                    <Box sx={{ mb: 2 }}>
                      <Chip label={`Security Score: ${scanResults.security_score}/10`} color="primary" sx={{ mr: 2 }} />
                      <Chip label={`Vulnerable: ${classified.VULNERABLE.length}`} color="error" sx={{ mr: 1 }} />
                      <Chip label={`Moderate: ${classified.MODERATE.length}`} color="warning" sx={{ mr: 1 }} />
                      <Chip label={`Info: ${classified.INFO.length}`} color="info" />
                    </Box>
                    <Grid container spacing={2}>
                      {Object.entries(classified).map(([category, vulns]) => (
                        <Grid item xs={12} md={4} key={category}>
                          <Paper elevation={2} sx={{ p: 2, minHeight: 200 }}>
                            <Typography variant="subtitle1" sx={{ fontWeight: 'bold', mb: 1 }}>
                              {category}
                            </Typography>
                            {vulns.length === 0 ? (
                              <Typography variant="body2" color="text.secondary">No findings</Typography>
                            ) : (
                              vulns.map((vuln, idx) => (
                                <Box key={idx} sx={{ mb: 1 }}>
                                  <Typography variant="body2" sx={{ fontWeight: 'bold' }}>{vuln.message}</Typography>
                                  <Typography variant="caption" color="text.secondary">
                                    {vuln.path} ({vuln.check_id})
                                  </Typography>
                                </Box>
                              ))
                            )}
                          </Paper>
                        </Grid>
                      ))}
                    </Grid>
                  </>;
                })()}
              </Box>
            )}
          </TabPanel>
          <TabPanel value={tabValue} index={1}>
            <ScanHistory onViewScan={handleViewScan} />
          </TabPanel>
        </Paper>
      </Box>
    </Container>
  );
}

export default App; 