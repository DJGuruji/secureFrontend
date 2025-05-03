import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Chip,
  IconButton,
  TablePagination,
  Tooltip,
} from '@mui/material';
import { format } from 'date-fns';
import VisibilityIcon from '@mui/icons-material/Visibility';
import axios from 'axios';

interface ScanHistoryProps {
  onViewScan: (scanId: string) => void;
}

interface ScanHistoryItem {
  id: string;
  file_name: string;
  scan_timestamp: string;
  security_score: number;
  total_vulnerabilities: number;
  severity_count: {
    ERROR: number;
    WARNING: number;
    INFO: number;
  };
  scan_duration: number;
  scan_status: string;
}

const ScanHistory: React.FC<ScanHistoryProps> = ({ onViewScan }) => {
  const [history, setHistory] = useState<ScanHistoryItem[]>([]);
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [totalCount, setTotalCount] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchHistory();
  }, [page, rowsPerPage]);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`http://localhost:8000/api/v1/scan/history`, {
        params: {
          limit: rowsPerPage,
          offset: page * rowsPerPage
        }
      });
      setHistory(response.data);
      setTotalCount(response.data.length);
    } catch (error) {
      console.error('Error fetching scan history:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  const getSeverityChip = (count: number, severity: string) => {
    if (count === 0) return null;
    
    const colorMap = {
      ERROR: 'error',
      WARNING: 'warning',
      INFO: 'info'
    };

    return (
      <Chip
        label={`${count} ${severity}`}
        color={colorMap[severity as keyof typeof colorMap] as any}
        size="small"
        sx={{ mr: 0.5 }}
      />
    );
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Scan History
      </Typography>
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>File Name</TableCell>
              <TableCell>Scan Time</TableCell>
              <TableCell>Security Score</TableCell>
              <TableCell>Vulnerabilities</TableCell>
              <TableCell>Duration</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {history.map((scan) => (
              <TableRow key={scan.id}>
                <TableCell>{scan.file_name}</TableCell>
                <TableCell>
                  {format(new Date(scan.scan_timestamp), 'PPpp')}
                </TableCell>
                <TableCell>
                  <Chip
                    label={`${scan.security_score}/10`}
                    color={scan.security_score >= 7 ? 'success' : scan.security_score >= 4 ? 'warning' : 'error'}
                  />
                </TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap' }}>
                    {getSeverityChip(scan.severity_count.ERROR, 'ERROR')}
                    {getSeverityChip(scan.severity_count.WARNING, 'WARNING')}
                    {getSeverityChip(scan.severity_count.INFO, 'INFO')}
                  </Box>
                </TableCell>
                <TableCell>
                  {scan.scan_duration.toFixed(2)}s
                </TableCell>
                <TableCell>
                  <Chip
                    label={scan.scan_status}
                    color={scan.scan_status === 'completed' ? 'success' : 'default'}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Tooltip title="View Details">
                    <IconButton
                      size="small"
                      onClick={() => onViewScan(scan.id)}
                    >
                      <VisibilityIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <TablePagination
        component="div"
        count={totalCount}
        page={page}
        onPageChange={handleChangePage}
        rowsPerPage={rowsPerPage}
        onRowsPerPageChange={handleChangeRowsPerPage}
      />
    </Box>
  );
};

export default ScanHistory; 