import React, { useState, useEffect } from 'react';
import { Table, Button, Tag } from 'antd';

interface AccessRight {
    objectUid: string;
    objectState: string;
    owner: string;
    operations: string[];
}

const AccessObtainedList: React.FC = () => {
    const [loading, setLoading] = useState(false);
    const [accessRights, setAccessRights] = useState<AccessRight[]>([]);

    const columns = [
        {
            title: 'Object UID',
            dataIndex: 'objectUid',
            key: 'objectUid',
        },
        {
            title: 'State',
            dataIndex: 'objectState',
            key: 'objectState',
            render: (state: string) => (
                <Tag color={state === 'Active' ? 'green' : 'orange'}>{state}</Tag>
            ),
        },
        {
            title: 'Owner',
            dataIndex: 'owner',
            key: 'owner',
        },
        {
            title: 'Granted Operations',
            dataIndex: 'operations',
            key: 'operations',
            render: (operations: string[]) => (
                <span>
                    {operations.map(op => (
                        <Tag key={op} color="blue">{op}</Tag>
                    ))}
                </span>
            ),
        },
    ];

    const fetchAccessRights = async () => {
        setLoading(true);
        try {
            // Handle API call to fetch access rights
            // const response = await api.listAccessRightsObtained();
            // setAccessRights(response.rights);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAccessRights();
    }, []);

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold text-gray-900">Access rights obtained</h1>
                <Button
                    type="primary"
                    onClick={fetchAccessRights}
                    loading={loading}
                    className="bg-blue-600 hover:bg-blue-700 border-0"
                >
                    Refresh
                </Button>
            </div>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>List of objects you have been granted access to, along with their current state, owner, and the operations you can perform.</p>
            </div >

            <Table
                dataSource={accessRights}
                columns={columns}
                rowKey="objectUid"
                loading={loading}
                pagination={{ pageSize: 10 }}
                className="border rounded-lg"
            />
        </div >
    );
};

export default AccessObtainedList;
