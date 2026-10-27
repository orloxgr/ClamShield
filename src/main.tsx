import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import UiErrorBoundary from './components/UiErrorBoundary';
import { reportUiFailure } from './lib/uiDiagnostics';
import './index.css';

window.addEventListener('error', event => {
  if (event.message) reportUiFailure({ stage: 'Running interface', code: 'JAVASCRIPT_ERROR', message: event.message, details: event.error?.stack });
});
window.addEventListener('unhandledrejection', event => reportUiFailure({ stage: 'Running interface', code: 'UNHANDLED_REJECTION', message: event.reason?.message || String(event.reason), details: event.reason?.stack }));

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <UiErrorBoundary><App /></UiErrorBoundary>
  </StrictMode>,
);
