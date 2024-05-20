"use client";

import { useGetUserCoursesQuery } from "../../../../redux/features/courses/coursesApi";
import { useTheme } from "next-themes";
import React from "react";
import Loader from "../../Loader/Loader";

type Props = {};

const AllUserCourses = (props: Props) => {
  const { theme, setTheme } = useTheme();
  const { isLoading, data, error } = useGetUserCoursesQuery({});

  const handleEdit = (courseId: string) => {
    // Navigate to edit page or open edit modal
    console.log(`Edit course with id: ${courseId}`);
  };

  const handleDelete = (courseId: string) => {
    // Implement delete functionality
    console.log(`Delete course with id: ${courseId}`);
    // Add delete functionality here
  };

  return (
    <div className={`mt-28 theme-${theme} flex-grow`}>
      {isLoading ? (
        <Loader />
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {data &&
            data.courses.map((course: any) => (
              <div
                key={course._id}
                className="card w-full bg-base-100 shadow-xl"
              >
                <div className="card-body">
                  <h2 className="card-title">{course.name}</h2>
                  <p>{course.description}</p>
                  <div className="card-actions justify-end">
                    <button
                      onClick={() => handleEdit(course._id)}
                      className="btn btn-primary"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(course._id)}
                      className="btn  bg-error"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </div>
            ))}
        </div>
      )}
      {error && <p className="text-red-500">Error loading courses</p>}
    </div>
  );
};

export default AllUserCourses;
