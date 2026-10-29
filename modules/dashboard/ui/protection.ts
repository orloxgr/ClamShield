export function dashboardProtectionState(status: any): 'protected' | 'engine-missing' | 'definitions-missing' | 'shield-off' {
    if (status?.hasEngine !== true || status.isSimulated)
        return 'engine-missing';
    if (status.hasDb !== true)
        return 'definitions-missing';
    return status.settings?.shieldEnabled === true ? 'protected' : 'shield-off';
}
