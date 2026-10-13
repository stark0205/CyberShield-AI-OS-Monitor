-- Normalization concepts applied to the CyberShield schema.
-- Read-only examples; this file does not create or alter database objects.
USE cybershield;

-- Functional dependencies in the current schema (examples):
--   usr:          uid -> uname, email, pwd_hash, role, created_at
--   device:       did -> uid, dname, os_type, ip_addr, reg_at
--   sec_event:    eid -> did, etype, details, pid, ppid, proc_state,
--                        cpu_pct, mem_mb, exe_name, ts
--   threat:       tid -> eid, confidence, risk_lvl, detected_at
--                 eid -> tid, confidence, risk_lvl, detected_at (eid UNIQUE)
--   investigation:inv_id -> tid, uid, status, notes, started_at, closed_at
--   resp_action:  raid -> inv_id, action_type, description, done_at
--
-- A functional dependency X -> Y means that each value of X determines
-- exactly one value of Y. Primary keys and UNIQUE constraints enforce
-- important dependencies in the database.

-- 1NF: each cell contains one value; no repeating groups or arrays.
-- The CyberShield tables use scalar columns for event and device fields.
-- A comma-separated list of process IDs in one column would violate 1NF.

-- 2NF: be in 1NF, and each non-key attribute must depend on the whole
-- candidate key, not just part of a composite key. The current tables use
-- single-column primary keys, so partial dependency on a primary key is
-- not present; this alone does not prove the higher normal forms.

-- 3NF: be in 2NF, and avoid non-key attributes depending transitively on
-- a key through another non-key attribute.
--
-- An illustrative unnormalized event report might contain:
--   EventReport(eid, did, dname, os_type, etype, exe_name)
-- with dependencies:
--   eid -> did, etype, exe_name
--   did -> dname, os_type
-- Since eid -> did -> dname, os_type, device facts are repeated for every
-- event from that device. The existing device/sec_event split stores
-- those facts separately. These queries show the two relations without
-- creating or modifying tables.
SELECT did, dname, os_type
FROM device;

SELECT eid, did, etype, exe_name
FROM sec_event;

-- BCNF: for every non-trivial functional dependency X -> Y, X must be a
-- superkey. BCNF is stricter than 3NF. A relation may satisfy 3NF but
-- violate BCNF when a determinant is not a superkey and the dependent
-- attribute is prime (part of a candidate key).
--
-- Example relation: Teaching(student, course, instructor)
-- Dependencies: (student, course) -> instructor; instructor -> course
-- Candidate keys: (student, course) and (student, instructor)
-- instructor -> course violates BCNF because instructor is not a key.
-- Decomposition: InstructorCourse(instructor, course) and
-- StudentInstructor(student, instructor). This decomposition is lossless,
-- but the first dependency may no longer be enforceable from either
-- component alone (a dependency-preservation tradeoff).

-- 4NF: be in BCNF and contain no non-trivial multivalued dependency
-- X ->> Y unless X is a superkey. This handles independent multi-valued
-- facts, not just functional dependencies.
--
-- Example DeviceFact(device, authorized_user, installed_tool), where a
-- device's authorized users are independent of its installed tools:
--   device ->> authorized_user
--   device ->> installed_tool
-- Store these as DeviceUser(device, authorized_user) and
-- DeviceTool(device, installed_tool), rather than pairing every user with
-- every tool in one three-column relation.
--
-- CyberShield currently has no independent multi-valued user/tool
-- attributes in one relation, so this is a syllabus concept, not a
-- required change to its schema.

-- 5NF (Project-Join NF): every non-trivial join dependency must be implied
-- by candidate keys. Decompose a relation only when the business rules say
-- that joining the smaller relations reconstructs exactly the original
-- valid tuples; otherwise the join may introduce spurious rows.
--
-- Example SupplierPartProject(supplier, part, project) may be decomposed
-- into SupplierPart, SupplierProject, and PartProject only if the domain
-- rules guarantee that all three pairwise relationships together define
-- exactly the valid triples. This is a conceptual example; the current
-- CyberShield schema has no such join dependency.

-- Relational schema design process:
-- 1. Identify attributes, candidate keys, and functional dependencies.
-- 2. Normalize to the required normal form (typically 3NF or BCNF).
-- 3. Check that decomposition is lossless and, where possible,
--    dependency-preserving.
-- 4. Consider 4NF/5NF only when multi-valued or join dependencies exist.
