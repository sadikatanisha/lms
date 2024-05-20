"use client";
import React, { useState } from "react";
import {
  useGetAllCoursesQuery,
  useUpdateCourseStatusMutation,
} from "../../../../redux/features/courses/coursesApi";
import { useTheme } from "next-themes";
import Loader from "../../Loader/Loader";

const AllCourses = () => {
  const { theme } = useTheme();
  const { isLoading, data, error } = useGetAllCoursesQuery({});
  const [updateCourseStatus] = useUpdateCourseStatusMutation();
  const [feedbacks, setFeedbacks] = useState<{ [key: string]: string }>({});
  const [statuses, setStatuses] = useState<{ [key: string]: string }>({});

  const handleFeedbackChange = (courseId: string, feedback: string) => {
    setFeedbacks((prev) => ({ ...prev, [courseId]: feedback }));
  };

  const handleStatusChange = (courseId: string, status: string) => {
    setStatuses((prev) => ({ ...prev, [courseId]: status }));
  };

  const handleUpdate = async (courseId: string) => {
    try {
      const feedback = feedbacks[courseId] || "";
      const status = statuses[courseId] || "Pending";

      await updateCourseStatus({
        courseId,
        status,
        adminFeedback: feedback,
      }).unwrap();
      alert("Course status updated successfully");
    } catch (error: any) {
      console.error(error);
      alert(`Failed to update course status: ${error.message}`);
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
                <th>Title</th>
                <th>Status</th>
                <th>Feedback</th>
                <th>Change Status</th>
                <th>Update</th>
              </tr>
            </thead>
            <tbody>
              {data &&
                data.courses.map((course: any) => (
                  <tr key={course._id}>
                    <td>
                      <div className="flex items-center gap-3">
                        <div className="avatar">
                          <div className="mask mask-squircle w-12 h-12">
                            <img
                              src={
                                course.image
                                  ? course.image.url
                                  : "/assets/default-avatar.png"
                              }
                              alt="Avatar"
                            />
                          </div>
                        </div>
                        <div>
                          <div className="font-bold">{course.name}</div>
                          <div className="text-sm opacity-50">
                            {course?.instructor?.email}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td>
                      {course.status === "approved" ? (
                        <span className="badge badge-success badge-md">
                          {course.status}
                        </span>
                      ) : (
                        <span className="badge badge-ghost gap-2 badge-md">
                          {course.status}
                        </span>
                      )}
                    </td>
                    <td>
                      <input
                        type="text"
                        placeholder="Type here"
                        className="input input-bordered input-md w-full max-w-xs"
                        value={feedbacks[course._id] || [course.adminFeedback]}
                        onChange={(e) =>
                          handleFeedbackChange(course._id, e.target.value)
                        }
                      />
                    </td>
                    <td>
                      <select
                        className="select select-bordered w-full max-w-xs"
                        value={statuses[course._id] || [course.status]}
                        onChange={(e) =>
                          handleStatusChange(course._id, e.target.value)
                        }
                      >
                        <option value="pending">Pending</option>
                        <option value="approved">Approve</option>
                        <option value="declined">Decline</option>
                      </select>
                    </td>
                    <td>
                      <button
                        className="btn btn-primary"
                        onClick={() => handleUpdate(course._id)}
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
      {error && <p className="text-red-500">Error loading courses</p>}
    </div>
  );
};

export default AllCourses;
