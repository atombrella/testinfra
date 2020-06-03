# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import re
from typing import Dict, List, Optional

from testinfra.modules.base import InstanceModule

# https://firewalld.org/documentation/man-pages/firewall-cmd.html


class Firewalld(InstanceModule):
    """Test firewalld rule exists"""

    # Maybe something about the IPSet?

    def services(self, *, permanent=False) -> List[str]:
        """Returns list of services enabled in firewalld

        Based on ouput of `firewall-cmd [--permanent] --get-services` command
        """
        if permanent:
            cmd = 'firewall-cmd {}--get-services'.format(
                '--permanent ' if permanent else ''
            )
        return self.check_output(cmd).split(' ')

    def info_zone(self, *, permanent=False, zone='public') -> \
            Dict[str, Dict[str, Optional[str]]]:
        """Returns info about a particular zone.

        Based on ouput of `firewall-cmd [--permanent] --info-zone=zone` command
        By default, the public zone is used.
        """
        info = {}
        cmd = 'firewall-cmd {} --info-zone=zone'.format(
            '--permanent ' if permanent else '',
        )
        output = self.check_output(cmd)
        current_zone = None
        for line in output:
            if re.match(r'^[a-z]', line):
                current_zone = line.strip()
                info[current_zone] = {}
                continue
            if current_zone:
                key, val = line.split(':', 1)
                info[current_zone][key] = val
        return info

    def get_default_zone(self, *, permanent=False):
        """Returns the default in firewalld

        Based on ouput of `firewall-cmd --get-default-zone` command
        """
        cmd = 'firewall-cmd {} --get-default-zone'.format(
            '--permanent ' if permanent else '',
        )
        return str(self.check_output(cmd))

    def ports(self, *, zone='public', permanent=False):
        """Returns list of open ports in firewalld

        Based on ouput of `firewall-cmd --zone=[zone] --list --ports` command
        """
        cmd = 'firewall-cmd {}{}--list --ports'.format(
            '--permanent ' if permanent else '',
            '--zone=%s ' % zone if zone else '',
        )
        return self.check_output(cmd).split(' ')
