import React, { useState, useEffect } from 'react';
import { Table, Button } from 'antd';

interface OwnedObject {
    uid: string;
    type: string;
    state: string;
    createdAt: string;
}

const ObjectsOwnedList: React.FC = () => {
    const [loading, setLoading] = useState(false);
    const [objects, setObjects] = useState<OwnedObject[]>([]);

    const columns = [
        {
            title: 'Object UID',
            dataIndex: 'uid',
            key: 'uid',
        },
        {
            title: 'Type',
            dataIndex: 'type',
            key: 'type',
        },
        {
            title: 'State',
            dataIndex: 'state',
            key: 'state',
        },
        {
            title: 'Created',
            dataIndex: 'createdAt',
            key: 'createdAt',
        },
    ];

    const fetchOwnedObjects = async () => {
        setLoading(true);
        try {
            // Handle API call to fetch owned objects
            // const response = await api.listOwnedObjects();
            // setObjects(response.objects);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchOwnedObjects();
    }, []);

    return (
        <div className="bg-white rounded-lg shadow-md p-6 m-4">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-2xl font-bold text-gray-900">Objects owned</h1>
                <Button
                    type="primary"
                    onClick={fetchOwnedObjects}
                    loading={loading}
                    className="bg-blue-600 hover:bg-blue-700 border-0"
                >
                    Refresh
                </Button>
            </div>

            <div className="mb-8 text-gray-600 space-y-2">
                <p>List of objects you own. </p>
                <p>As an owner, you can perform any operation on these objects and grant access rights to other users.</p>
            </div>

            <Table
                dataSource={objects}
                columns={columns}
                rowKey="uid"
                loading={loading}
                pagination={{ pageSize: 10 }}
                className="border rounded-lg"
            />
        </div>
    );
};

export default ObjectsOwnedList;
