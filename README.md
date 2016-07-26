net-shovel
==========

net-shovel is a tool for internet traffic accounting and monitoring.
It is designed to be run on a server that is in between the users and the internet.

` Users, AP -> Switch -> net-shovel -> Modem -> Internet`

## Planned Features
### Core
- Each person receives their own account for tracking data
- Track internet data usage based on the source MAC address
- Associate multiple MAC addresses per user account
- Disable Internet access once data usage quota has been reached for account
- Allocate bandwidth fairly for each user (QoS)
- Manage DHCP
- Keep a record of data usage per account

### Web interface
- User can add new devices by authenticating with net-shovel
	- net-shovel will associate the source MAC address with the given account
- Allow users to authenticate and view their monthly data usage
- Admin page for managing users
	- Reset password
	- View associated MACs
	- Add/Remove MAcs
- Admin page for viewing data user summary for all users
- Public page for viewing total data usage
- Display current bandwidth utilization
	- Total
	- Per account/MAC
