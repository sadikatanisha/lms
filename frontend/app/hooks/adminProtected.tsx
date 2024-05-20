import { redirect } from "next/navigation";
import { useSelector } from "react-redux";

interface ProtectedProps {
  children: React.ReactNode;
}

export function AdminProtected({ children }: ProtectedProps) {
  const { user } = useSelector((state: any) => state.auth);
  if (user) {
    const isAdmin = user?.role === "admin";
    return isAdmin ? children : redirect("/");
  }
}
export function InstructroProtected({ children }: ProtectedProps) {
  const { user } = useSelector((state: any) => state.auth);
  if (user) {
    const isInstructor = user?.role === "instructor";
    return isInstructor ? children : redirect("/");
  }
}
