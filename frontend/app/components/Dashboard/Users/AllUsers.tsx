"use client";

import {
  useGetAllUserQuery,
  useUpdateUserRoleMutation,
} from "../../../../redux/features/user/userApi";
import { useTheme } from "next-themes";
import React, { useEffect, useState } from "react";
import Loader from "../../Loader/Loader";
import toast from "react-hot-toast";

type Props = {};

const AllUsers = (props: Props) => {
  const { theme } = useTheme();
  const { isLoading, data, error, refetch } = useGetAllUserQuery(
    {},
    { refetchOnMountOrArgChange: true }
  );
  const [updateUserRole, { error: updateError, isSuccess }] =
    useUpdateUserRoleMutation();

  const [role, setRole] = useState<{ [key: string]: string }>({});
  useEffect(() => {
    if (updateError) {
      if ("data" in updateError) {
        const errorMessage = updateError as any;
        toast.error(errorMessage.data.message);
      }
    }
    if (isSuccess) {
      refetch();
      toast.success("User role updated successfully");
    }
  }, [updateError, isSuccess]);

  const handleRoleChange = (userId: string, userRole: string) => {
    setRole((prev) => ({
      ...prev,
      [userId]: userRole,
    }));
  };

  const handleUpdateRole = async (userId: string) => {
    if (role[userId]) {
      try {
        await updateUserRole({ id: userId, role: role[userId] }).unwrap();
        alert("User role updated successfully");
      } catch (error) {
        console.error("Failed to update user role:", error);
        alert("Failed to update user role");
      }
    }
  };

  return (
    <div className={`mt-28 theme-${theme} flex-grow`}>
      {isLoading ? (
        <Loader />
      ) : (
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Role</th>
                <th>Change Roles</th>
                <th>Update</th>
              </tr>
            </thead>
            <tbody>
              {data &&
                data.users.map((user: any) => (
                  <tr key={user._id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="avatar">
                          <div className="mask mask-squircle w-12 h-12">
                            <img
                              src={
                                user.avatar
                                  ? user.avatar.url
                                  : "/assets/default-avatar.png"
                              }
                              alt="Avatar"
                            />
                          </div>
                        </div>
                        <div>
                          <div className="font-bold">{user.name}</div>
                          <div className="text-sm opacity-50">{user.email}</div>
                        </div>
                      </div>
                    </td>
                    <td>
                      {user.role}
                      <br />
                      <span className="badge badge-ghost badge-sm">
                        {user.role === "admin" ? "Administrator" : "User"}
                      </span>
                    </td>
                    <td>
                      <select
                        className="select select-bordered w-full max-w-xs"
                        value={role[user._id] || user.role}
                        onChange={(e) =>
                          handleRoleChange(user._id, e.target.value)
                        }
                      >
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                        <option value="instructor">Instructor</option>
                      </select>
                    </td>
                    <td>
                      <button
                        className="btn btn-primary"
                        onClick={() => handleUpdateRole(user._id)}
                      >
                        Update
                      </button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
      {error && <p className="text-red-500">Error loading users</p>}
    </div>
  );
};

export default AllUsers;
