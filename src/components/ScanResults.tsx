import React from 'react';
import {
  Box,
  Typography,
  List,
  ListItem,
  ListItemText,
  Chip,
  Divider,
  CircularProgress,
} from '@mui/material';
import ErrorIcon from '@mui/icons-material/Error';
import WarningIcon from '@mui/icons-material/Warning';
import InfoIcon from '@mui/icons-material/Info';

interface ScanResultsProps {
  results: {
    security_score: number;
    vulnerabilities: Array<{
      check_id: string;
      path: string;
      start: { line: number };
      end: { line: number };
      extra: {
        message: string;
        severity: string;
      };
    }>;
    severity_count: {
      ERROR: number;
      WARNING: number;
      INFO: number;
    };
  };
}

const SeverityIcon = ({ severity }: { severity: string }) => {
  switch (severity) {
    case 'ERROR':
      return <ErrorIcon color="error" />;
    case 'WARNING':
      return <WarningIcon color="warning" />;
    case 'INFO':
      return <InfoIcon color="info" />;
    default:
      return <InfoIcon color="info" />;
  }
};

const ScanResults: React.FC<ScanResultsProps> = ({ results }) => {
  const { security_score, vulnerabilities, severity_count } = results;

  return (
    <Box>
      <Box sx={{ mb: 3, textAlign: 'center' }}>
        <Typography variant="h4" gutterBottom>
          Security Score
        </Typography>
        <Box
          sx={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 120,
            height: 120,
            borderRadius: '50%',
            bgcolor: 'primary.main',
            color: 'white',
            position: 'relative',
          }}
        >
          <CircularProgress
            variant="determinate"
            value={security_score * 10}
            size={120}
            thickness={4}
            sx={{
              position: 'absolute',
              color: 'white',
              opacity: 0.3,
            }}
          />
          <Typography variant="h3" component="div">
            {security_score}/10
          </Typography>
        </Box>
      </Box>

      <Box sx={{ mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Vulnerability Summary
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
          <Chip
            icon={<ErrorIcon />}
            label={`${severity_count.ERROR} Errors`}
            color="error"
          />
          <Chip
            icon={<WarningIcon />}
            label={`${severity_count.WARNING} Warnings`}
            color="warning"
          />
          <Chip
            icon={<InfoIcon />}
            label={`${severity_count.INFO} Info`}
            color="info"
          />
        </Box>
      </Box>

      <Divider sx={{ my: 2 }} />

      <Typography variant="h6" gutterBottom>
        Detailed Findings
      </Typography>
      <List>
        {vulnerabilities.map((vuln, index) => (
          <React.Fragment key={index}>
            <ListItem alignItems="flex-start">
              <ListItemText
                primary={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <SeverityIcon severity={vuln.extra.severity} />
                    <Typography variant="subtitle1">
                      {vuln.extra.message}
                    </Typography>
                  </Box>
                }
                secondary={
                  <>
                    <Typography
                      component="span"
                      variant="body2"
                      color="text.primary"
                    >
                      {vuln.path}:{vuln.start.line}-{vuln.end.line}
                    </Typography>
                    <br />
                    <Typography
                      component="span"
                      variant="body2"
                      color="text.secondary"
                    >
                      Check ID: {vuln.check_id}
                    </Typography>
                  </>
                }
              />
            </ListItem>
            {index < vulnerabilities.length - 1 && <Divider />}
          </React.Fragment>
        ))}
      </List>
    </Box>
  );
};

export default ScanResults; 