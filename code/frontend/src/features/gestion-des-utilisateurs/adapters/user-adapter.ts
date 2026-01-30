import type { UserApi } from '../types/api';
import type { UserRecord } from '../types/user-record';

export function mapUserToRecord(user: UserApi, canDelete?: boolean): UserRecord {
  return {
    id: String(user.id),
    firstName: user.first_name,
    lastName: user.last_name,
    email: user.email,
    canDelete,
  };
}

export function mapUsersToRecords(
  users: UserApi[],
  getCanDelete?: (user: UserApi) => boolean,
): UserRecord[] {
  return users.map((user) => mapUserToRecord(user, getCanDelete?.(user)));
}
