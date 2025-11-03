set(CMAKE_PREFIX_PATH "/opt/Qt/6.10.0/gcc_64/lib/cmake")
find_package(Qt6 6.10.0 REQUIRED COMPONENTS Core Gui Widgets)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)


add_executable(${PROJECT_NAME}_test test.cpp)
add_executable(${PROJECT_NAME}_test_as_dir as_dir.cpp)
add_executable(${PROJECT_NAME}_test_as_node as_node.cpp)

target_link_libraries(
        ${PROJECT_NAME}_test PRIVATE ${PROJECT_NAME}_lib Qt6::Core Qt6::Gui Qt6::Widgets)
target_link_libraries(
        ${PROJECT_NAME}_test_as_dir PRIVATE ${PROJECT_NAME}_lib)
target_link_libraries(
        ${PROJECT_NAME}_test_as_node PRIVATE ${PROJECT_NAME}_lib)
