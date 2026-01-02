Import-Module .\src\Forensikit\Forensikit.psd1 -Force

# Create a custom profile equivalent to -Mode Deep
New-ForensikitCustomProfile -Mode Deep -Path .\deep_profile.json

# Interval example (every 6 hours)
$params = @{
	Name = 'deepEvery6h'
	CustomProfilePath = '.\deep_profile.json'
	Every = (New-TimeSpan -Hours 6)
	OutputPath = '.\Output'
	CopyProfile = $true
	SiemFormat = 'None'
}
Register-ForensikitSchedule @params

# Weekly example (every Sunday at 23:59)
$params = @{
	Name = 'weeklySunday'
	CustomProfilePath = '.\deep_profile.json'
	DaysOfWeek = 'Sunday'
	At = (New-TimeSpan -Hours 23 -Minutes 59)
	OutputPath = '.\Output'
	CopyProfile = $true
}
Register-ForensikitSchedule @params

# Monthly example (every 15th day at 12:00)
$params = @{
	Name = 'monthly15th'
	CustomProfilePath = '.\deep_profile.json'
	DaysOfMonth = 15
	AtMonthly = (New-TimeSpan -Hours 12)
	OutputPath = '.\Output'
	CopyProfile = $true
}
Register-ForensikitSchedule @params

# Unregister
Unregister-ForensikitSchedule -Name deepEvery6h
