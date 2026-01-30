import { redirect } from 'next/navigation';

export default function NewUserPage() {
  redirect('/gestion-des-utilisateurs/liste');
}
