import './server/core/logging';
import { startServer } from './server/bootstrap';
import { reportBackendStartupFailure } from './server/core/startupFailure';

startServer().catch(reportBackendStartupFailure);
