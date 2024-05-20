import { useSelector } from "react-redux";
import { RootState } from "@/redux/store";
export default function useUserAuth() {
  const user = useSelector((state: RootState) => state.auth.user);
  if (user) {
    return true;
  } else {
    return false;
  }
}

// import { useSelector } from "react-redux";

// export default function userAuth() {
//   const { user } = useSelector((state: any) => state.auth);
//   if (user) {
//     return true;
//   } else {
//     return false;
//   }
// }
